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

#define SEPARATOR 0xbad
#define CLEAR_PTE_THRESHOLD 501752

#define MAX_N_FIND 131071U
#define PMM_MIXED 1

#define DRAM_MODE 0
#define NVRAM_MODE 1
#define NVRAM_INTENSIVE_MODE 2
#define SWITCH_MODE 3
#define NVRAM_WRITE_MODE 5

struct pte_callback_context_t {
	u32 n_found;
	u32 switch_found_dram;
	u32 switch_found_nvram;
	u32 n_to_find;
	u32 n_backup;
	u32 backup_switch_found_dram;
	u32 backup_switch_found_nvram;

	size_t curr_pid_idx;

	addr_info_t found_addrs[MAX_N_FIND];
	addr_info_t backup_addrs[MAX_N_FIND]; // prevents a second page walk
	addr_info_t switch_addrs_dram[MAX_N_FIND / 2];
	addr_info_t switch_addrs_nvram[MAX_N_FIND / 2];
	addr_info_t backup_switch_addrs_dram[MAX_N_FIND / 2];
	addr_info_t backup_switch_addrs_nvram[MAX_N_FIND / 2];
} static g_context = { 0 };

unsigned long g_last_addr_dram = 0;
unsigned long g_last_addr_nvram = 0;

int g_last_pid_dram = 0;
int g_last_pid_nvram = 0;

unsigned long long pages_walked = 0;
unsigned long last_addr_clear = 0;
unsigned long long total_migrations = 0;
unsigned long long dram_migrations[5];
unsigned long long nvram_migrations[5];
int migration_type = 0;

int g_switch_act = 1;
int g_thresh_act = 1;

// ==================================================================================
// CALLBACK FUNCTIONS
// ==================================================================================

static int pte_callback_dram(pte_t *ptep, unsigned long addr,
			     unsigned long next, struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	pte_t old_pte, new_pte;

	// If found all, save last addr
	if (ctx->n_found == ctx->n_to_find) {
		pr_debug(
			"Dram callback: found enough pages, storing last addr %lx\n",
			addr);
		g_last_addr_dram = addr;
		return 1;
	}

	// If page is not present, write protected, or not in DRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, DRAM_POOL)) {
		return 0;
	}

	if (!pte_young(*ptep)) {
		// Send to NVRAM
		ctx->found_addrs[ctx->n_found].addr = addr;
		ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
		return 0;
	}

	if (!pte_dirty(*ptep) &&
	    (ctx->n_backup < (ctx->n_to_find - ctx->n_found))) {
		// Add to backup list
		ctx->backup_addrs[ctx->n_backup].addr = addr;
		ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
	}

	old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
	new_pte = pte_mkold(old_pte); // unset modified bit
	new_pte = pte_mkclean(new_pte); // unset dirty bit
	ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, new_pte);
	return 0;
}

static int pte_callback_dram_switch(pte_t *ptep, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	pte_t old_pte, new_pte;

	// If found all, save last addr
	if (ctx->switch_found_dram >= ctx->n_to_find) {
		pr_debug(
			"Dram callback: found enough pages, storing last addr %lx\n",
			addr);
		g_last_addr_dram = addr;
		return 1;
	}

	// If page is not present, write protected, or not in DRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, DRAM_POOL)) {
		return 0;
	}

	// not accessed and not dirty
	if (!pte_young(*ptep)) {
		// Send to NVRAM
		ctx->switch_addrs_dram[ctx->switch_found_dram].addr = addr;
		ctx->switch_addrs_dram[ctx->switch_found_dram].pid_idx =
			ctx->curr_pid_idx;

		ctx->switch_found_dram += 1;
		return 0;
	}

	// accessed but not dirty
	if (!pte_dirty(*ptep) &&
	    (ctx->backup_switch_found_dram < ctx->n_to_find)) {
		// Add to backup list
		ctx->backup_switch_addrs_dram[ctx->backup_switch_found_dram]
			.addr = addr;
		ctx->backup_switch_addrs_dram[ctx->backup_switch_found_dram]
			.pid_idx = ctx->curr_pid_idx;
		ctx->backup_switch_found_dram += 1;
	}

	old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
	new_pte = pte_mkold(old_pte); // unset modified bit
	new_pte = pte_mkclean(new_pte); // unset dirty bit
	ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, new_pte);
	return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_force(pte_t *ptep, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	pte_t old_pte, new_pte;

	// If found all save last addr
	if (ctx->n_found == ctx->n_to_find) {
		g_last_addr_nvram = addr;
		return 1;
	}

	// If page is not present, write protected, or not in NVRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, NVRAM_POOL)) {
		return 0;
	}

	if (pte_young(*ptep) && pte_dirty(*ptep)) {
		// Send to DRAM (priority)
		ctx->found_addrs[ctx->n_found].addr = addr;
		ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
		return 0;
	}

	if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
		// Add to backup list
		ctx->backup_addrs[ctx->n_backup].addr = addr;
		ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
	}

	old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
	new_pte = pte_mkold(old_pte); // unset modified bit
	new_pte = pte_mkclean(new_pte); // unset dirty bit
	ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, new_pte);

	return 0;
}

// ----------------------------------------------------------------------------------

// used only for debug in ctl (NVRAM_WRITE_MODE)
static int pte_callback_nvram_write(pte_t *ptep, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	// If found all save last addr
	if (ctx->n_found == ctx->n_to_find) {
		g_last_addr_nvram = addr;
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
			ctx->found_addrs[ctx->n_found].addr = addr;
			ctx->found_addrs[ctx->n_found++].pid_idx =
				ctx->curr_pid_idx;
		} else if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
			// Add to backup list
			ctx->backup_addrs[ctx->n_backup].addr = addr;
			ctx->backup_addrs[ctx->n_backup++].pid_idx =
				ctx->curr_pid_idx;
		}
	}

	return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_intensive(pte_t *ptep, unsigned long addr,
					unsigned long next,
					struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	// If found all save last addr
	if (ctx->n_found == ctx->n_to_find) {
		g_last_addr_nvram = addr;
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
			ctx->found_addrs[ctx->n_found].addr = addr;
			ctx->found_addrs[ctx->n_found++].pid_idx =
				ctx->curr_pid_idx;
			return 0;
		}

		if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
			// Add to backup list
			ctx->backup_addrs[ctx->n_backup].addr = addr;
			ctx->backup_addrs[ctx->n_backup++].pid_idx =
				ctx->curr_pid_idx;
		}
	}

	return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_switch(pte_t *ptep, unsigned long addr,
				     unsigned long next, struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;

	// If found all save last addr
	if (ctx->switch_found_nvram >= ctx->n_to_find) {
		g_last_addr_nvram = addr;
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
			ctx->switch_addrs_nvram[ctx->switch_found_nvram].addr =
				addr;
			ctx->switch_addrs_nvram[ctx->switch_found_nvram]
				.pid_idx = ctx->curr_pid_idx;
			ctx->switch_found_nvram += 1;
		}

		// Add to backup list
		else if (ctx->backup_switch_found_nvram < ctx->n_to_find) {
			ctx->backup_switch_addrs_nvram
				[ctx->backup_switch_found_nvram]
					.addr = addr;
			ctx->backup_switch_addrs_nvram
				[ctx->backup_switch_found_nvram]
					.pid_idx = ctx->curr_pid_idx;
			ctx->backup_switch_found_nvram += 1;
		}
	}

	return 0;
}

static int pte_callback_nvram_clear(pte_t *ptep, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	pte_t old_pte, new_pte;

	// If  page is not present, write protected, or page is not in NVRAM node
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
	    !is_page_in_pool(*ptep, NVRAM_POOL)) {
		return 0;
	}

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

typedef int (*pte_entry_handler_t)(pte_t *, unsigned long addr,
				   unsigned long next, struct mm_walk *);

static const char *print_mode(pte_entry_handler_t h)
{
	if (h == pte_callback_nvram_switch)
		return "NVRAM-switch";
	else if (h == pte_callback_nvram_intensive)
		return "NVRAM-intensive";
	else if (h == pte_callback_nvram_write)
		return "NVRAM-write";
	else if (h == pte_callback_nvram_force)
		return "NVRAM-force";
	else if (h == pte_callback_nvram_clear)
		return "NVRAM-clear";
	else if (h == pte_callback_dram)
		return "DRAM";
	else
		return "Unknown";
}

static int do_page_walk(pte_entry_handler_t pte_handler,
			struct pte_callback_context_t *ctx,
			const int lst_pid_idx, const unsigned long last_addr)
{
	struct mm_walk_ops mem_walk_ops = { .pte_entry = pte_handler };

	int i;
	unsigned long left = last_addr;
	unsigned long right = PIDs[lst_pid_idx].end_addr;

	pr_debug(
		"Page walk. Mode:%s; n:%d/%d; last_pid:%d(%d); last_addr:%lx.\n",
		print_mode(pte_handler), ctx->n_found, ctx->n_to_find,
		pid_nr(PIDs[lst_pid_idx].__pid), lst_pid_idx, last_addr);

	// start at lst_pid_idx's last_addr, walk through all pids and finish by
	// addresses less than last_addr's lst_pid_idx; (i.e go twice through idx ==
	// lst_pid_idx)
	for (i = lst_pid_idx; i != lst_pid_idx + PIDs_size + 1; ++i) {
		int idx = i % PIDs_size;
		int next_idx = (idx + 1) % PIDs_size;
		struct task_struct *t =
			get_pid_task(PIDs[idx].__pid, PIDTYPE_PID);
		if (!t) {
			continue;
		}

		pr_debug(
			"Walk iteration [%d] {pid:%d(%d); left:%lx; right: %lx}\n",
			i, pid_nr(PIDs[idx].__pid), idx, left, right);

		if (t->mm != NULL) {
			mmap_read_lock(t->mm);
			ctx->curr_pid_idx = idx;
			g_walk_page_range(t->mm, left, right, &mem_walk_ops,
					  ctx);
			mmap_read_unlock(t->mm);
		}
		put_task_struct(t);

		// TODO: review this if
		if (ctx->n_found >= ctx->n_to_find ||
		    max(ctx->switch_found_dram + ctx->backup_switch_found_dram,
			ctx->switch_found_nvram +
				ctx->backup_switch_found_nvram) >=
			    ctx->n_to_find) {
			pr_debug(
				"Has found enough (%u) pages. Last pid is %d(%d).",
				ctx->n_found, pid_nr(PIDs[idx].__pid), idx);
			return idx;
		}

		// TODO check this (MIGRATING UNBOUND PAGES)
		// PIDs[idx].start_addr

		left = PIDs[next_idx].start_addr;

		if ((i + 1) % PIDs_size ==
		    lst_pid_idx) { // second run through lst_pid_idx
			if (!last_addr) {
				break; // first run has already covered all address range.
			}
			right = last_addr; // + page?
		}
	}

	pr_debug("Page walk has completed. Found %u of %u pages.\n",
		 ctx->n_found, ctx->n_to_find);

	return lst_pid_idx;
}

/**
 * returns 0 if success, -1 if error occurs
 **/
int mem_walk(struct pte_callback_context_t *ctx, const int n, const int mode)
{
	pte_entry_handler_t pte_handler;
	int *last_pid_idx = &g_last_pid_nvram;
	unsigned long *last_addr = &g_last_addr_nvram;

	ctx->n_to_find = n;
	ctx->n_backup = 0;
	ctx->n_found = 0;

	switch (mode) {
	case DRAM_MODE:
		last_pid_idx = &g_last_pid_dram;
		last_addr = &g_last_addr_dram;
		pte_handler = pte_callback_dram;
		break;
	case NVRAM_MODE:
		pte_handler = pte_callback_nvram_force;
		break;
	case NVRAM_WRITE_MODE:
		pte_handler = pte_callback_nvram_write;
		break;
	case NVRAM_INTENSIVE_MODE:
		pte_handler = pte_callback_nvram_intensive;
		break;
	default:
		printk("Unrecognized mode.\n");
		return -1;
	}

	*last_pid_idx =
		do_page_walk(pte_handler, ctx, *last_pid_idx, *last_addr);
	pr_debug(
		"Memory walk complete. found:%d; backed-up:%d; last_pid:%d(%d) "
		"last_addr:%lx;\n",
		ctx->n_found, ctx->n_backup, pid_nr(PIDs[*last_pid_idx].__pid),
		*last_pid_idx, *last_addr);

	if (ctx->n_found < ctx->n_to_find && (ctx->n_backup > 0)) {
		unsigned i = 0;
		int remaining = ctx->n_to_find - ctx->n_found;
		pr_debug("Using backup addresses (require %u, has %d)\n",
			 remaining, ctx->n_backup);
		for (i = 0; (i < ctx->n_backup && i < remaining); ++i) {
			ctx->found_addrs[ctx->n_found].addr =
				ctx->backup_addrs[i].addr;
			ctx->found_addrs[ctx->n_found].pid_idx =
				ctx->backup_addrs[i].pid_idx;
			++ctx->n_found;
		}
	}
	return 0;
}

// ----------------------------------------------------------------------------------

static int clear_nvram_ptes(struct pte_callback_context_t *ctx)
{
	struct task_struct *t = NULL;
	struct mm_walk_ops mem_walk_ops = { .pte_entry =
						    pte_callback_nvram_clear };
	int i;

	pr_debug("Cleaning NVRAM PTEs");

	for (i = 0; i < PIDs_size; i++) {
		t = get_pid_task(PIDs[i].__pid, PIDTYPE_PID);
		if (!t) {
			pr_warn("Can't resolve task (%d).\n",
				pid_nr(PIDs[i].__pid));
			continue;
		}
		ctx->curr_pid_idx = i;
		spin_lock(&t->mm->page_table_lock);
		g_walk_page_range(t->mm, 0, MAX_ADDRESS, &mem_walk_ops, ctx);
		spin_unlock(&t->mm->page_table_lock);
		put_task_struct(t);
	}
	return 0;
}

// ----------------------------------------------------------------------------------

/**
 * return 0 if success, (-1 otherwise)
 **/
int switch_walk(struct pte_callback_context_t *ctx, u32 n)
{
	u32 nvram_found;
	u32 dram_found;

	ctx->switch_found_nvram = 0;
	ctx->switch_found_dram = 0;
	ctx->backup_switch_found_dram = 0;
	ctx->backup_switch_found_nvram = 0;
	ctx->n_to_find = n;

	g_last_pid_nvram = do_page_walk(pte_callback_nvram_switch, ctx,
					g_last_pid_nvram, g_last_addr_nvram);

	nvram_found = ctx->switch_found_nvram;

	ctx->n_to_find = min(nvram_found + ctx->backup_switch_found_nvram, n);

	pr_info("Found %u pages in NVRAM", nvram_found);
	pr_info("Found %u backup pages in NVRAM",
		ctx->backup_switch_found_nvram);

	if (ctx->n_to_find > nvram_found) {
		u32 i = 0;
		u32 limit = ctx->n_to_find - nvram_found;
		for (i = 0; i < limit; i++) {
			ctx->switch_addrs_nvram[nvram_found + i] =
				ctx->backup_switch_addrs_nvram[i];
		}
	}

	g_last_pid_dram = do_page_walk(pte_callback_dram_switch, ctx,
				       g_last_pid_dram, g_last_addr_dram);

	dram_found = ctx->switch_found_dram;

	ctx->n_to_find =
		min(dram_found + ctx->backup_switch_found_dram, ctx->n_to_find);

	pr_info("Found %u pages in DRAM", dram_found);
	pr_info("Found %u backup pages in DRAM", ctx->backup_switch_found_dram);

	if (ctx->n_to_find > dram_found) {
		u32 i = 0;
		u32 limit = ctx->n_to_find - dram_found;
		for (i = 0; i < limit; i++) {
			ctx->switch_addrs_dram[nvram_found + i] =
				ctx->backup_switch_addrs_dram[i];
		}
	}

	return 0;
}

// returns 0 if success, negative value otherwise
int find_candidate_pages(struct pte_callback_context_t *ctx, u32 n_pages,
			 int mode)
{
	switch (mode) {
	case DRAM_MODE:
	case NVRAM_MODE:
	case NVRAM_WRITE_MODE:
	case NVRAM_INTENSIVE_MODE:
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

static u32 kmod_migrate_pages(struct pte_callback_context_t *, int n_pages,
			      int mode);

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
							 NVRAM_INTENSIVE_MODE);
				migrate_us = tsc_to_usec(tsc_rd() - tsc_start);

				n_migrated += num;
				total_migrations += num;
				nvram_migrations[NVRAM_INTENSIVE_MODE] += num;
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
			u32 num = kmod_migrate_pages(ctx, n_pages, DRAM_MODE);
			dram_migrations[DRAM_MODE] += num;
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
			u32 num = kmod_migrate_pages(ctx, n_pages, NVRAM_MODE);
			nvram_migrations[NVRAM_MODE] += num;
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

static int do_switch(struct pte_callback_context_t *ctx)
{
	pr_info("Switching: %d\n", ctx->n_to_find);
	return do_migration(ctx->switch_addrs_dram, ctx->n_to_find,
			    NVRAM_POOL) +
	       do_migration(ctx->switch_addrs_nvram, ctx->n_to_find, DRAM_POOL);
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
	if (rc) {
		pr_debug("No candidates were found (%lldus)\n",
			 find_candidates_us);
		return 0;
	}

	pr_debug("Found %d candidates (%lldus)\n", ctx->n_found,
		 find_candidates_us);

	nr = 0;
	tsc_start = tsc_rd();
	migration_type = mode;
	switch (mode) {
	case DRAM_MODE:
		nr = do_migration(ctx->found_addrs, ctx->n_found, NVRAM_POOL);
		pr_debug("DRAM migration of %d pages took %lldus", nr,
			 tsc_to_usec(tsc_rd() - tsc_start));
		break;
	case NVRAM_MODE:
	case NVRAM_WRITE_MODE:
	case NVRAM_INTENSIVE_MODE:
		nr = do_migration(ctx->found_addrs, ctx->n_found, DRAM_POOL);
		pr_debug("NVRAM migration of %d pages took %lldus", nr,
			 tsc_to_usec(tsc_rd() - tsc_start));
		break;
	case SWITCH_MODE:
		nr = do_switch(ctx);
		pr_debug("Switch of %d pages took %lldus", nr,
			 tsc_to_usec(tsc_rd() - tsc_start));
		break;
	}
	return nr;
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
