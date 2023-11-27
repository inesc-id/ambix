/**
 * @file    placement.c
 * @author  INESC-ID
 * @date    26 jul 2023
 * @version 2.1.1
 * @brief  Page walker for finding page table entries' r/m bits. Intended for
 * the 5.10.0 linux kernel. Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code provided by reza
 * karimi <r68karimi@gmail.com>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#define pr_fmt(fmt) "ambix.PLACEMENT: " fmt

#include <generated/utsrelease.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/init.h> // Macros used to mark up functions e.g., __init __exit
#include <linux/kernel.h> // Contains types, macros, functions for the kernel
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/module.h> // Core header for loading LKMs into the kernel
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/shmem_fs.h>
#include <linux/signal.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/mm.h>

#include <linux/mm_inline.h>
#include <linux/mmzone.h> // Contains conversion between pfn and node id (NUMA node)
#include <linux/mutex.h>
#include <linux/pagewalk.h>
#include <linux/string.h>

#include "config.h"
#include "find_kallsyms_lookup_name.h"
#include "memory_info.h"
#include "perf_counters.h"
#include "pid_management.h"
#include "placement.h"
#include "tsc.h"
#include "kernel_symbols.h"
#include "migrate.h"
#include "priority_queue.h"

#define SEPARATOR 0xbad
#define CLEAR_PTE_THRESHOLD 501752

#define MAX_N_FIND 131071U
#define PMM_MIXED 1

#define DEMOTE_PAGES 0
#define EVICT_FAST_TIER 1
#define PROMOTE_YOUNG_PAGES 2
#define SWITCH_MODE 3
#define PROMOTE_DIRTY_PAGES 4

typedef int (*pte_entry_handler_t)(pte_t *, unsigned long addr,
				   unsigned long next, struct mm_walk *);

struct pte_callback_context_t {
	u32 n_found;
	u32 n_to_find;
	u32 walk_iter;
	unsigned long last_addr;
	size_t curr_pid_idx;

	priority_queue fast_tier_pages;
	priority_queue slow_tier_pages;
} static g_context = { 0 };

int g_last_dram_idx = 0;
unsigned long g_last_dram_addr = 0;

int g_pte_clear_window_start_idx = 0;
int g_pte_clear_window_end_idx = 0;

unsigned long g_pte_clear_window_start_addr = 0;
unsigned long g_pte_clear_window_end_addr = 0;

unsigned long long pages_walked = 0;
unsigned long long total_migrations = 0;
unsigned long long dram_migrations[5];
unsigned long long nvram_migrations[5];
int migration_type = 0;

const int g_switch_act = 1;
const int g_thresh_act = 1;

// ==================================================================================
// CALLBACK FUNCTIONS
// ==================================================================================

static int fast_tier_scan_callback(pte_t *ptep, unsigned long addr,
				   unsigned long next, struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;
	pte_t old_pte, new_pte;
	enum access_freq_t access_freq;

	ctx->last_addr = addr;
	ctx->walk_iter++;

	if (ctx->n_found == ctx->n_to_find) {
		pr_debug("Dram callback: found enough pages, last addr %lx\n",
			 addr);
		return 1;
	}

	if (ctx->walk_iter == 2 * CLEAR_PTE_THRESHOLD) {
		return 1;
	}

	// If page is not present, write protected, or not in DRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, DRAM_POOL)) {
		return 0;
	}

	if (!pte_young(*ptep) && !pte_dirty(*ptep)) {
		access_freq = COLD_PAGE;
		ctx->n_found++;
		goto enqueue_page;
	} else if (pte_young(*ptep)) {
		access_freq = WARM_ACCESSED_PAGE;
	} else if (pte_dirty(*ptep)) {
		access_freq = WARM_DIRTY_PAGE;
	} else {
		access_freq = HOT_PAGE;
	}

	old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
	new_pte = pte_mkold(old_pte); // unset modified bit
	new_pte = pte_mkclean(new_pte); // unset dirty bit
	ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, new_pte);

enqueue_page:
	enqueue_address(&ctx->fast_tier_pages, addr, ctx->curr_pid_idx,
			access_freq);

	return 0;
}

// ----------------------------------------------------------------------------------

static int slow_tier_exhaustive_scan_callback(pte_t *ptep, unsigned long addr,
					      unsigned long next,
					      struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;
	enum access_freq_t access_freq;

	ctx->last_addr = addr;
	ctx->walk_iter++;

	if (ctx->n_found == ctx->n_to_find) {
		return 1;
	}

	if (ctx->walk_iter == 2 * CLEAR_PTE_THRESHOLD) {
		return 1;
	}

	// If page is not present, write protected, or not in NVRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, NVRAM_POOL)) {
		return 0;
	}

	if (pte_young(*ptep) && pte_dirty(*ptep)) {
		access_freq = HOT_PAGE;
		ctx->n_found++;
	} else if (pte_young(*ptep)) {
		access_freq = WARM_ACCESSED_PAGE;
	} else if (pte_dirty(*ptep)) {
		access_freq = WARM_DIRTY_PAGE;
	} else {
		access_freq = COLD_PAGE;
	}

	enqueue_address(&ctx->slow_tier_pages, addr, ctx->curr_pid_idx,
			access_freq);
	return 0;
}

// ----------------------------------------------------------------------------------

// used only for debug in ctl (PROMOTE_DIRTY_PAGES)
static int slow_tier_write_priority_callback(pte_t *ptep, unsigned long addr,
					     unsigned long next,
					     struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	ctx->last_addr = addr;
	ctx->walk_iter++;

	if (ctx->walk_iter == 2 * CLEAR_PTE_THRESHOLD) {
		return 1;
	}

	if (ctx->n_found == ctx->n_to_find) {
		return 1;
	}

	// If page is not present, write protected, or not in NVRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, NVRAM_POOL)) {
		return 0;
	}

	if (pte_dirty(*ptep)) {
		if (pte_young(*ptep)) {
			// Send to DRAM (priority)
			enqueue_address(&ctx->slow_tier_pages, addr,
					ctx->curr_pid_idx, HOT_PAGE);
			ctx->n_found++;
		} else {
			// Add to backup list
			enqueue_address(&ctx->slow_tier_pages, addr,
					ctx->curr_pid_idx, COLD_PAGE);
		}
	}

	return 0;
}

// ----------------------------------------------------------------------------------

static int slow_tier_access_priority_callback(pte_t *ptep, unsigned long addr,
					      unsigned long next,
					      struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	ctx->last_addr = addr;
	ctx->walk_iter++;

	if (ctx->n_found == ctx->n_to_find) {
		return 1;
	}

	if (ctx->walk_iter == 2 * CLEAR_PTE_THRESHOLD) {
		return 1;
	}

	// If page is not present, write protected, or not in NVRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, NVRAM_POOL)) {
		return 0;
	}

	if (pte_young(*ptep)) {
		if (pte_dirty(*ptep)) {
			// Send to DRAM (priority)
			enqueue_address(&ctx->slow_tier_pages, addr,
					ctx->curr_pid_idx, HOT_PAGE);
			ctx->n_found++;
			return 0;
		}

		enqueue_address(&ctx->slow_tier_pages, addr, ctx->curr_pid_idx,
				WARM_ACCESSED_PAGE);
	}

	return 0;
}

static int slow_tier_clear_pte_callback(pte_t *ptep, unsigned long addr,
					unsigned long next,
					struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;
	pte_t old_pte, new_pte;

	ctx->last_addr = addr;
	ctx->walk_iter++;

	if (ctx->n_found == ctx->n_to_find) {
		return 1;
	}

	if (ctx->walk_iter == 2 * CLEAR_PTE_THRESHOLD) {
		return 1;
	}

	// If  page is not present, write protected, or page is not in NVRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, NVRAM_POOL)) {
		return 0;
	}

	ctx->n_found++;

	old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
	new_pte = pte_mkold(old_pte); // unset modified bit
	new_pte = pte_mkclean(new_pte); // unset dirty bit
	ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, new_pte);

	return 0;
}

/*
-------------------------------------------------------------------------------

PAGE WALKERS

-------------------------------------------------------------------------------
*/

static int do_page_walk(int idx, unsigned long start_addr,
			unsigned long end_addr, pte_entry_handler_t pte_handler,
			struct pte_callback_context_t *ctx)
{
	struct mm_walk_ops mem_walk_ops = { .pte_entry = pte_handler };
	struct task_struct *t;
	struct mm_struct *mm;

	ctx->curr_pid_idx = idx;
	t = get_pid_task(PIDs[idx].__pid, PIDTYPE_PID);
	mm = get_task_mm(t);

	if (!t) {
		return 0;
	}

	do {
		if (mm) {
			pr_info("Page Walk {pid[%d]:%d; left:%lx; right: %lx}\n",
				idx, pid_nr(PIDs[idx].__pid), start_addr,
				end_addr);

			ctx->walk_iter = 0;

			mmap_read_lock(mm);
			g_walk_page_range(mm, start_addr, end_addr,
					  &mem_walk_ops, ctx);
			mmap_read_unlock(mm);
		}

		if (ctx->n_found >= ctx->n_to_find)
			break;

		if (start_addr == ctx->last_addr)
			break;

		start_addr = ctx->last_addr;
	} while (ctx->last_addr < end_addr);

	mmput(mm);
	put_task_struct(t);

	return 0;
}

static addr_info_t walk_tasks_page_range(int start_idx, int end_idx,
					 unsigned long start_addr,
					 unsigned long end_addr,
					 pte_entry_handler_t pte_handler,
					 struct pte_callback_context_t *ctx)
{
	int idx = start_idx;
	unsigned long left = start_addr;
	unsigned long right = MAX_ADDRESS;
	addr_info_t last_addr;
	int rewalk_first_pid = 1;

	if (start_idx == end_idx && start_addr < end_addr) {
		right = end_addr;
		rewalk_first_pid = 0;
	}

	for (;;) {
		do_page_walk(idx, left, right, pte_handler, ctx);

		if (ctx->n_found >= ctx->n_to_find) {
			break;
		}

		if (idx == end_idx) {
			if (rewalk_first_pid) {
				rewalk_first_pid = 0;
			} else {
				break;
			}
		}

		idx = (idx + 1) % PIDs_size;
		left = 0;
		right = (idx != end_idx) ? MAX_ADDRESS : end_addr;
	}

	last_addr.pid_idx = idx;
	last_addr.addr = ctx->last_addr;

	return last_addr;
}

static int do_fast_tier_page_walk(pte_entry_handler_t pte_handler,
				  struct pte_callback_context_t *ctx)
{
	addr_info_t last_addr;

	pr_info("Fast tier page walk\n");

	last_addr = walk_tasks_page_range(g_last_dram_idx, g_last_dram_idx,
					  g_last_dram_addr, g_last_dram_addr,
					  pte_handler, ctx);

	g_last_dram_idx = last_addr.pid_idx;
	g_last_dram_addr = last_addr.addr;

	return address_count(&ctx->fast_tier_pages);
}

static int do_slow_tier_page_walk(pte_entry_handler_t pte_handler,
				  struct pte_callback_context_t *ctx)
{
	addr_info_t last_addr;

	pr_info("Slow tier page walk\n");

	last_addr = walk_tasks_page_range(g_pte_clear_window_start_idx,
					  g_pte_clear_window_end_idx,
					  g_pte_clear_window_start_addr,
					  g_pte_clear_window_end_addr,
					  pte_handler, ctx);

	g_pte_clear_window_start_idx = last_addr.pid_idx;
	g_pte_clear_window_start_addr = last_addr.addr;

	return address_count(&ctx->slow_tier_pages);
}

static int clear_nvram_ptes(struct pte_callback_context_t *ctx)
{
	addr_info_t last_addr;

	ctx->n_to_find = 8 * CLEAR_PTE_THRESHOLD;

	pr_info("Clearing NVRAM PTEs\n");
	last_addr = walk_tasks_page_range(g_pte_clear_window_end_idx,
					  g_pte_clear_window_end_idx,
					  g_pte_clear_window_end_addr,
					  g_pte_clear_window_start_addr,
					  slow_tier_clear_pte_callback, ctx);

	g_pte_clear_window_start_idx = g_pte_clear_window_end_idx;
	g_pte_clear_window_start_addr = g_pte_clear_window_end_addr;
	g_pte_clear_window_end_idx = last_addr.pid_idx;
	g_pte_clear_window_end_addr = last_addr.addr;

	return ctx->n_found;
}

/**
 * returns number of pages found if success, 0 if error occurs
 **/
int mem_walk(struct pte_callback_context_t *ctx, const int n, const int mode)
{
	pte_entry_handler_t pte_handler;

	switch (mode) {
	case DEMOTE_PAGES:
		pte_handler = fast_tier_scan_callback;
		return min(n, do_fast_tier_page_walk(pte_handler, ctx));

		break;
	case EVICT_FAST_TIER:
		pte_handler = slow_tier_exhaustive_scan_callback;
		break;
	case PROMOTE_DIRTY_PAGES:
		pte_handler = slow_tier_write_priority_callback;
		break;
	case PROMOTE_YOUNG_PAGES:
		pte_handler = slow_tier_access_priority_callback;
		break;
	default:
		printk("Unrecognized mode.\n");
		return -1;
	}

	return min(n, do_slow_tier_page_walk(pte_handler, ctx));
}

/**
 * return number of pages to switch if success, (0 otherwise)
 **/
int switch_walk(struct pte_callback_context_t *ctx, u32 n)
{
	int hot_pages_found =
		do_slow_tier_page_walk(slow_tier_access_priority_callback, ctx);
	pr_info("Found %d    %d    %d    %d/%d pages in NVRAM\n",
		ctx->slow_tier_pages.index[HOT_PAGE],
		ctx->slow_tier_pages.index[WARM_ACCESSED_PAGE],
		ctx->slow_tier_pages.index[WARM_DIRTY_PAGE], hot_pages_found,
		n);

	ctx->n_to_find = min((u32)hot_pages_found, n);

	// ?Maybe skip the next page walk with numbers >0 but lower than const
	if (ctx->n_to_find == 0) {
		pr_info("Skipped DRAM walk\n");
		return 0;
	}

	// TODO: This should not be done in this function, separate var to n_found_(dram/pmem)
	ctx->n_found = 0;

	int cold_pages_found =
		do_fast_tier_page_walk(fast_tier_scan_callback, ctx);
	pr_info("Found %d   %d    %d    %d/%d pages in DRAM\n",
		ctx->fast_tier_pages.index[COLD_PAGE],
		ctx->fast_tier_pages.index[WARM_DIRTY_PAGE],
		ctx->fast_tier_pages.index[WARM_ACCESSED_PAGE],
		cold_pages_found, ctx->n_to_find);

	enum access_freq_t slow_tier_freq = HOT_PAGE;
	enum access_freq_t fast_tier_freq = COLD_PAGE;

	u32 warmer_pages = ctx->slow_tier_pages.index[slow_tier_freq--];
	u32 colder_pages = ctx->fast_tier_pages.index[fast_tier_freq++];

	if (warmer_pages == colder_pages) {
		colder_pages += ctx->fast_tier_pages.index[fast_tier_freq];
		warmer_pages += ctx->slow_tier_pages.index[slow_tier_freq];
		return min(n, min(warmer_pages, colder_pages));
	}

	// TODO: This method of calculating the number of pages to switch is terible, but it is reasonable for now

	if (warmer_pages > colder_pages) {
		colder_pages += ctx->fast_tier_pages.index[fast_tier_freq++];
	} else if (warmer_pages < colder_pages) {
		warmer_pages += ctx->slow_tier_pages.index[slow_tier_freq--];
	}

	if (warmer_pages > colder_pages) {
		colder_pages += ctx->fast_tier_pages.index[fast_tier_freq];
	} else if (warmer_pages < colder_pages) {
		warmer_pages += ctx->slow_tier_pages.index[slow_tier_freq];
	}

	return min(n, min(warmer_pages, colder_pages));
}

// returns number of pages if success, negative value otherwise
int find_candidate_pages(struct pte_callback_context_t *ctx, u32 n_pages,
			 int mode)
{
	clear_queue(&ctx->fast_tier_pages);
	clear_queue(&ctx->slow_tier_pages);

	ctx->n_found = 0;
	ctx->n_to_find = n_pages;

	switch (mode) {
	case DEMOTE_PAGES:
	case EVICT_FAST_TIER:
	case PROMOTE_DIRTY_PAGES:
	case PROMOTE_YOUNG_PAGES:
		BUG_ON(n_pages > MAX_N_FIND);
		return mem_walk(ctx, n_pages, mode);
	case SWITCH_MODE:
		BUG_ON(n_pages > (MAX_N_FIND / 2));
		return switch_walk(ctx, n_pages);
	default:
		pr_info("Unrecognized mode.\n");
		return -1;
	}
}

/**
 * returns number of migrated pages
 */
static u32 kmod_migrate_pages(struct pte_callback_context_t *ctx,
			      const int nr_pages, const int mode)
{
	int rc;
	u32 nr;
	u64 tsc_start, find_candidates_us;
	pr_debug("It was requested %d page migrations\n", nr_pages);

	tsc_start = tsc_rd();
	rc = find_candidate_pages(ctx, nr_pages, mode);
	find_candidates_us = tsc_to_usec(tsc_rd() - tsc_start);
	if (rc <= 0) {
		pr_debug("No candidates were found (%lldus)\n",
			 find_candidates_us);
		return 0;
	}

	pr_debug("Found %d candidates (%lldus)\n", rc, find_candidates_us);

	nr = 0;
	tsc_start = tsc_rd();
	migration_type = mode;
	switch (mode) {
	case DEMOTE_PAGES:
		nr = do_migration(&ctx->fast_tier_pages, rc, NVRAM_POOL,
				  COLDER_PAGES_FIRST);
		pr_debug("DRAM migration of %d pages took %lldus", nr,
			 tsc_to_usec(tsc_rd() - tsc_start));
		break;
	case EVICT_FAST_TIER:
	case PROMOTE_DIRTY_PAGES:
	case PROMOTE_YOUNG_PAGES:
		nr = do_migration(&ctx->slow_tier_pages, rc, DRAM_POOL,
				  WARMER_PAGES_FIRST);
		pr_debug("NVRAM migration of %d pages took %lldus", nr,
			 tsc_to_usec(tsc_rd() - tsc_start));
		break;
	case SWITCH_MODE:
		pr_info("Switching: %d\n", rc);

		nr = do_migration(&ctx->fast_tier_pages, rc, NVRAM_POOL,
				  COLDER_PAGES_FIRST) +
		     do_migration(&ctx->slow_tier_pages, rc, DRAM_POOL,
				  WARMER_PAGES_FIRST);

		pr_debug("Switch of %d pages took %lldus", nr,
			 tsc_to_usec(tsc_rd() - tsc_start));
		break;
	}
	return nr;
}

// MAIN ENTRY POINT
int ambix_check_memory(void)
{
	u32 n_migrated = 0;
	int i = 0;
	struct pte_callback_context_t *ctx = &g_context;

	pr_debug("Memory migration routine\n");
	pr_info("Migrated %llu since start", total_migrations);

	unsigned long long ts = ktime_get_real_fast_ns();
	pr_info("dram,%llu,%llu,%llu,%llu,%llu,%llu", dram_migrations[0],
		dram_migrations[1], dram_migrations[2], dram_migrations[3],
		dram_migrations[4], ts);

	pr_info("nvram,%llu,%llu,%llu,%llu,%llu,%llu", nvram_migrations[0],
		nvram_migrations[1], nvram_migrations[2], nvram_migrations[3],
		nvram_migrations[4], ts);
	for (i = 0; i < 5; i++) {
		dram_migrations[i] = 0;
		nvram_migrations[i] = 0;
	}

	mutex_lock(&PIDs_mtx);
	refresh_pids();
	if (PIDs_size == 0) {
		pr_debug("No bound processes...\n");
		goto release_return_acm;
	}

	walk_ranges_usage();
	pr_info("Ambix DRAM Usage: %d\n", get_memory_usage_percent(DRAM_POOL));
	pr_info("Ambix NVRAM Usage: %d\n",
		get_memory_usage_percent(NVRAM_POOL));

	pr_info("System DRAM Usage: %d\n",
		get_real_memory_usage_per(DRAM_POOL));
	pr_info("System NVRAM Usage: %d\n",
		get_real_memory_usage_per(NVRAM_POOL));

	if (g_switch_act) {
		u64 pmm_bw = 0;

		if (PMM_MIXED) {
			pmm_bw = perf_counters_pmm_writes() +
				 perf_counters_pmm_reads();
		} else {
			pmm_bw = perf_counters_pmm_writes();
		}

		pr_info("BANDWIDTH PMM = %lld", pmm_bw);
		pr_debug("ppm_bw: %lld, NVRAM_BW_THRESH: %d\n", pmm_bw,
			 NVRAM_BANDWIDTH_THRESHOLD);
		if (pmm_bw >= NVRAM_BANDWIDTH_THRESHOLD) {
			u64 tsc_start = tsc_rd(), clear_us, migrate_us;

			// ? This should probably be done either at the end of the previous ambix run
			// ? or there should be a delay after it is called
			clear_nvram_ptes(ctx);
			clear_us = tsc_to_usec(tsc_rd() - tsc_start);

			if (get_memory_usage_percent(DRAM_POOL) <
				    DRAM_MEM_USAGE_TARGET_PERCENT &&
			    get_real_memory_usage_per(DRAM_POOL) <
				    AMBIX_DRAM_HARD_LIMIT) {
				u64 n_bytes, n_bytes_sys;
				u32 n_pages, num;

				// [DRAM_USAGE_LIMIT (%) - DRAM_USAGE_NODE (%)] * TOTAL_MEM_NODE
				// (#bytes)
				n_bytes_sys = ((AMBIX_DRAM_HARD_LIMIT -
						get_real_memory_usage_per(
							DRAM_POOL)) *
					       get_memory_total(DRAM_POOL)) /
					      100;
				n_bytes =
					((DRAM_MEM_USAGE_LIMIT_PERCENT -
					  get_memory_usage_percent(DRAM_POOL)) *
					 get_memory_total_ratio(DRAM_POOL)) /
					100;

				n_pages = min(n_bytes_sys / PAGE_SIZE,
					      min(n_bytes / PAGE_SIZE,
						  (u64)MAX_N_FIND));

				tsc_start = tsc_rd();
				num = kmod_migrate_pages(ctx, n_pages,
							 PROMOTE_YOUNG_PAGES);
				migrate_us = tsc_to_usec(tsc_rd() - tsc_start);

				n_migrated += num;
				total_migrations += num;
				nvram_migrations[PROMOTE_YOUNG_PAGES] += num;
				pr_info("NVRAM->DRAM [B]: Migrated %d intensive pages out of %d."
					" (%lldus cleanup; %lldus migration) \n",
					num, n_pages, clear_us, migrate_us);
			} else {
				u32 num;
				tsc_start = tsc_rd();
				num = kmod_migrate_pages(ctx, MAX_N_FIND / 2,
							 SWITCH_MODE);
				nvram_migrations[SWITCH_MODE] += num;
				dram_migrations[SWITCH_MODE] += num;
				migrate_us = tsc_to_usec(tsc_rd() - tsc_start);
				n_migrated += num;
				total_migrations += num;
				total_migrations += num;
				pr_info("DRAM<->NVRAM [B]: Switched %d pages."
					" (%lldus cleanup; %lldus migration)\n",
					num, clear_us, migrate_us);
			}
		}
	}
	if (g_thresh_act) {
		pr_debug(
			"Thresholds: DRAM limit %d of %d; NVRAM target %d of %d\n",
			get_memory_usage_percent(DRAM_POOL),
			DRAM_MEM_USAGE_LIMIT_PERCENT,
			get_memory_usage_percent(NVRAM_POOL),
			NVRAM_MEM_USAGE_TARGET_PERCENT);
		if ((get_memory_usage_percent(DRAM_POOL) >
		     DRAM_MEM_USAGE_LIMIT_PERCENT) &&
		    ((get_memory_usage_percent(NVRAM_POOL) <
		      NVRAM_MEM_USAGE_TARGET_PERCENT) &&
		     get_real_memory_usage_per(NVRAM_POOL) <
			     AMBIX_NVRAM_HARD_LIMIT)) {
			u64 n_bytes_sys =
				((AMBIX_NVRAM_HARD_LIMIT -
				  get_real_memory_usage_per(NVRAM_POOL)) *
				 get_memory_total(NVRAM_POOL)) /
				100;
			u64 n_bytes =
				min((get_memory_usage_percent(DRAM_POOL) -
				     DRAM_MEM_USAGE_TARGET_PERCENT) *
					    get_memory_total_ratio(DRAM_POOL),
				    (NVRAM_MEM_USAGE_TARGET_PERCENT -
				     get_memory_usage_percent(NVRAM_POOL)) *
					    get_memory_total_ratio(
						    NVRAM_POOL)) /
				100;
			u32 n_pages =
				min(n_bytes_sys / PAGE_SIZE,
				    min(n_bytes / PAGE_SIZE, (u64)MAX_N_FIND));
			u64 const tsc_start = tsc_rd();
			u32 num =
				kmod_migrate_pages(ctx, n_pages, DEMOTE_PAGES);
			dram_migrations[DEMOTE_PAGES] += num;
			u64 const migrate_us =
				tsc_to_usec(tsc_rd() - tsc_start);
			n_migrated += num;
			total_migrations += num;
			pr_info("DRAM->NVRAM [U]: Migrated %d out of %d pages."
				" (%lldus)\n",
				num, n_pages, migrate_us);
		} else if (!g_switch_act &&
			   (get_memory_usage_percent(NVRAM_POOL) >
			    NVRAM_MEM_USAGE_LIMIT_PERCENT) &&
			   (get_memory_usage_percent(DRAM_POOL) <
			    DRAM_MEM_USAGE_TARGET_PERCENT) &&
			   get_real_memory_usage_per(DRAM_POOL) <
				   AMBIX_DRAM_HARD_LIMIT) {
			s64 n_bytes =
				min((get_memory_usage_percent(NVRAM_POOL) -
				     NVRAM_MEM_USAGE_TARGET_PERCENT) *
					    get_memory_total_ratio(NVRAM_POOL),
				    (DRAM_MEM_USAGE_TARGET_PERCENT -
				     get_memory_usage_percent(DRAM_POOL)) *
					    get_memory_total_ratio(DRAM_POOL)) /
				100;
			s64 n_bytes_sys =
				((AMBIX_DRAM_HARD_LIMIT -
				  get_real_memory_usage_per(DRAM_POOL)) *
				 get_memory_total(DRAM_POOL)) /
				100;
			u32 n_pages = min(n_bytes / PAGE_SIZE,
					  n_bytes_sys / PAGE_SIZE);
			u64 const tsc_start = tsc_rd();
			u32 num = kmod_migrate_pages(ctx, n_pages,
						     EVICT_FAST_TIER);
			nvram_migrations[EVICT_FAST_TIER] += num;
			u64 const migrate_us =
				tsc_to_usec(tsc_rd() - tsc_start);
			n_migrated += num;
			total_migrations += num;
			pr_info("NVRAM->DRAM [U]: Migrated %d out of %d pages."
				" (%lldus)\n",
				num, n_pages, migrate_us);
		}
	}

release_return_acm:
	mutex_unlock(&PIDs_mtx);
	return n_migrated;
}

/*
-------------------------------------------------------------------------------

MODULE INIT/EXIT

-------------------------------------------------------------------------------
*/

int ambix_init(void)
{
	pr_debug("Initializing\n");

	import_symbols();

	size_t i;
	for (i = 0; i < get_pool_size(DRAM_POOL); ++i) {
		int n = get_pool_nodes(DRAM_POOL)[i];
		if (!node_online(n)) {
			pr_err("DRAM node %d is not online.\n", n);
			return -1;
		}
	}
	for (i = 0; i < get_pool_size(NVRAM_POOL); ++i) {
		int n = get_pool_nodes(NVRAM_POOL)[i];
		if (!node_online(n)) {
			pr_err("NVRAM node %d is not online.\n", n);
			return -1;
		}
	}

	return 0;
}

void ambix_cleanup(void)
{
	pr_debug("Cleaning up\n");
}
