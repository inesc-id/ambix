/**
 * @file    placement.c
 * @author  INESC-ID
 * @date    26 jul 2023
 * @version 2.2.0
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
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/module.h>
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
#include <linux/mmzone.h>
#include <linux/mutex.h>
#include <linux/pagewalk.h>
#include <linux/string.h>

#include "config.h"
#include "find_kallsyms_lookup_name.h"
#include "sys_mem_info.h"
#include "perf_counters.h"
#include "vm_management.h"
#include "placement.h"
#include "tsc.h"
#include "kernel_symbols.h"
#include "migrate.h"
#include "ambix_types.h"

// Maximum number of pages that can be walked during a call to g_walk_page_range
#define FAST_TIER_WALK_THRESHOLD 33554432

#define MAX_N_FIND 65536U
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
	struct pid *curr_pid;

	struct vm_heat_map fast_tier_pages;
	struct vm_heat_map slow_tier_pages;
	struct memory_range_t *tracking_range;
} static g_context = { 0 };

struct vm_area_walk_t last_fast_tier_scan;
struct vm_area_walk_t last_slow_tier_scan;

unsigned long long pages_walked = 0;
unsigned long long total_migrations = 0;
unsigned long long dram_migrations[5];
unsigned long long nvram_migrations[5];
int migration_type = 0;

const int g_switch_act = 0;
const int g_thresh_act = 0;

int current_average = 0;
int value_count = 0;

#define SCALE_FACTOR 1000 // For precision

unsigned long long temp_dram_usage = 0;
unsigned long long temp_nvram_usage = 0;
unsigned long long temp_cold_page_count = 0;
unsigned long long temp_hot_page_count = 0;

unsigned long long histogram[1024] = { 0 };

int g_threshold = 4;

int page_cpupid_xchg_last(struct page *page, int cpupid)
{
	unsigned long old_flags, flags;
	int last_cpupid;

	do {
		old_flags = flags = page->flags;
		last_cpupid = page_cpupid_last(page);

		flags &= ~(LAST_CPUPID_MASK << LAST_CPUPID_PGSHIFT);
		flags |= (cpupid & LAST_CPUPID_MASK) << LAST_CPUPID_PGSHIFT;
	} while (
		unlikely(cmpxchg(&page->flags, old_flags, flags) != old_flags));

	return last_cpupid;
}

// ==================================================================================
// CALLBACK FUNCTIONS
// ==================================================================================

static int page_scan_callback(pte_t *ptep, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	struct pte_callback_context_t *ctx =
		(struct pte_callback_context_t *)walk->private;
	pte_t old_pte, new_pte;
	struct page *page = NULL;
	bool managed_by_ambix = 0;

	ctx->last_addr = addr;
	ctx->walk_iter++;

	if (ctx->walk_iter == FAST_TIER_WALK_THRESHOLD) {
		return 1;
	}

	// If page is not present or read-only
	if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep)) {
		return 0;
	}

	if (ctx->tracking_range && addr >= ctx->tracking_range->end_addr) {
	next_area:
		struct memory_range_t *next_vm_area =
			list_next_entry(ctx->tracking_range, node);

		// Looped back to the start of the circular list
		if (next_vm_area->start_addr <
		    ctx->tracking_range->start_addr) {
			ctx->tracking_range = NULL;
		} else {
			if (next_vm_area->end_addr < addr) {
				ctx->tracking_range = next_vm_area;
				goto next_area;
			}

			ctx->tracking_range = next_vm_area;
			ctx->tracking_range->fast_tier_bytes = 0;
			ctx->tracking_range->slow_tier_bytes = 0;
		}
	}


	if (ctx->tracking_range && ctx->tracking_range->start_addr <= addr &&
	    ctx->tracking_range->end_addr > addr)
		managed_by_ambix = 1;

	page = g_vm_normal_page(walk->vma, addr, *ptep);

	int last = page_cpupid_last(page);
	int new_value = last;

	int age_shift = LAST_CPUPID_SHIFT - 6;

	int age = last >> age_shift;

	if (last == 0x1fffff) {
		new_value = 0;
		age = 0;
	}

	if ((new_value & ((1 << 8) - 1)) >= 128)
		goto skip_update;

	int cold_candidate = 0;

	if (!pte_young(*ptep) && !pte_soft_dirty(*ptep)) {
		if ((new_value & ((1 << 7) - 1)) > 0)
			new_value--;
		cold_candidate = 1;
	}
	if (pte_young(*ptep)) {
		new_value += 2;
	}
	if (pte_soft_dirty(*ptep)) {
		new_value++;
	}

skip_update:

	if (age == 0) {
		value_count++;
	}

	if (age < 64)
		new_value += 1 << age_shift;

	page_cpupid_xchg_last(page, new_value);

	int page_score = (new_value & ((1 << 7) - 1));

	histogram[page_score % 1024]++;

	if (is_page_in_pool(*ptep, DRAM_POOL)) {
		temp_dram_usage += PAGE_SIZE;

		if (managed_by_ambix) {
			ctx->tracking_range->fast_tier_bytes += PAGE_SIZE;
		}

		if (age > 10 && page_score < g_threshold && cold_candidate) {
			heat_map_add_page(&ctx->fast_tier_pages, addr,
					  ctx->curr_pid, COLD_PAGE);
			temp_cold_page_count++;
		}

	} else if (is_page_in_pool(*ptep, NVRAM_POOL)) {
		temp_nvram_usage += PAGE_SIZE;
		if (managed_by_ambix) {
			ctx->tracking_range->slow_tier_bytes += PAGE_SIZE;
		}


		if ((age <= 2 && !cold_candidate) ||
		    (page_score > 6 * g_threshold && !cold_candidate)) {
			heat_map_add_page(&ctx->slow_tier_pages, addr,
					  ctx->curr_pid, HOT_PAGE);
			temp_hot_page_count++;
		}
	}

	if (new_value > last) {
		old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
		new_pte = pte_mkold(old_pte); // unset modified bit
		new_pte = pte_clear_soft_dirty(new_pte); // unset dirty bit
		ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte,
					new_pte);
	}

	return 0;
}

/*
-------------------------------------------------------------------------------

PAGE WALKERS

-------------------------------------------------------------------------------
*/

void calculate_treshold(void)
{
	u64 total_pages = get_memory_total(DRAM_POOL) / PAGE_SIZE;
	u64 temp = 0;
	int i;
	for (i = 255; i > 0; i--) {
		temp += histogram[i];
		if (temp > total_pages)
			break;
	}

	g_threshold = i + 1;

	//pr_info("g_threshold: %d\n", g_threshold);
}

static int do_page_walk(struct bound_program_t *program,
			unsigned long start_addr, unsigned long end_addr,
			pte_entry_handler_t pte_handler,
			struct pte_callback_context_t *ctx)
{
	struct mm_walk_ops mem_walk_ops = { .pte_entry = pte_handler };
	struct task_struct *t;
	struct mm_struct *mm;

	struct pid *pid_p = program->__pid;

	ctx->curr_pid = pid_p;

	t = get_pid_task(pid_p, PIDTYPE_PID);
	if (!t)
		return 0;

	mm = get_task_mm(t);
	if (!mm) {
		put_task_struct(t);
		return 0;
	}

	ctx->last_addr = start_addr;
	mmap_read_lock(mm);
	g_walk_page_range(mm, start_addr, end_addr, &mem_walk_ops, ctx);
	mmap_read_unlock(mm);

	if (ctx->walk_iter < FAST_TIER_WALK_THRESHOLD) {
		program->fast_tier_bytes = temp_dram_usage;
		program->slow_tier_bytes = temp_nvram_usage;
		pr_info("Usage (bytes) dram: %llu  pmem: %llu\n",
			temp_dram_usage, temp_nvram_usage);
		temp_nvram_usage = 0;
		temp_dram_usage = 0;

		pr_info("Pid: %d, Hot: %llu, Cold: %llu\n",
			pid_nr(program->__pid), temp_hot_page_count,
			temp_cold_page_count);
		temp_hot_page_count = 0;
		temp_cold_page_count = 0;
	}

	if (!program->migrations_enabled) {
		heat_map_clear(&ctx->fast_tier_pages);
		heat_map_clear(&ctx->slow_tier_pages);
	}

	mmput(mm);
	put_task_struct(t);

	return 1;
}

struct vm_area_walk_t
walk_vm_ranges_constrained(int start_pid, unsigned long start_addr, int end_pid,
			   unsigned long end_addr,
			   pte_entry_handler_t pte_handler,
			   struct pte_callback_context_t *ctx)
{
	struct bound_program_t *bound_program;
	struct vm_area_walk_t ret;
	ret.start_pid = start_pid;
	ret.start_addr = start_addr;
	int walk_count = 0;
	int i;

	mutex_lock(&bound_list_mutex);

	ctx->walk_iter = 0;

repeat:

	list_for_each_entry (bound_program, &bound_program_list, node) {
		if (pid_nr(bound_program->__pid) != start_pid &&
		    walk_count == 0)
			continue;

		if (list_entry_is_head(bound_program, &bound_program_list,
				       node) &&
		    start_addr == 0) {
			calculate_treshold();

			char histogram_str[10752];

			char *where = histogram_str;
			for (i = 0; i < 256; i++) {
				size_t printed = sprintf(where, "%d:%llu, ", i,
							 histogram[i]);
				histogram[i] = 0;
				where += printed;
			}

			*where = '\n';

			trace_printk("%s", histogram_str);
		}

		ctx->tracking_range = find_memory_range_for_address(
			pid_nr(bound_program->__pid), start_addr);

		if (ctx->tracking_range) {
			ctx->tracking_range->fast_tier_bytes = 0;
			ctx->tracking_range->slow_tier_bytes = 0;
		}

		do_page_walk(bound_program, start_addr, MAX_ADDRESS,
			     pte_handler, ctx);

		start_addr = 0;

		ret.end_pid = pid_nr(bound_program->__pid);

		if (ctx->walk_iter < FAST_TIER_WALK_THRESHOLD)
			ret.end_addr = 0;

		else
			ret.end_addr = ctx->last_addr;

		walk_count++;

		if (ctx->walk_iter == FAST_TIER_WALK_THRESHOLD)
			goto out;
	}

	if (walk_count == 0) {
		walk_count++;
		goto repeat;
	}

out:

	if (ctx->walk_iter <= 1) {
		ret.end_addr = 0;
	}

	mutex_unlock(&bound_list_mutex);

	return ret;
}

struct vm_area_walk_t walk_all_vm_ranges(int start_pid,
					 unsigned long start_addr,
					 pte_entry_handler_t pte_handler,
					 struct pte_callback_context_t *ctx)
{
	return walk_vm_ranges_constrained(start_pid, start_addr, start_pid,
					  start_addr, pte_handler, ctx);
}

static int do_ambix_page_walk(pte_entry_handler_t pte_handler,
			      struct pte_callback_context_t *ctx)
{
	struct vm_area_walk_t last_vm_area =
		walk_all_vm_ranges(last_fast_tier_scan.end_pid,
				   last_fast_tier_scan.end_addr, pte_handler,
				   ctx);

	last_fast_tier_scan.start_pid = last_fast_tier_scan.end_pid;
	last_fast_tier_scan.start_addr = last_fast_tier_scan.end_addr;

	last_fast_tier_scan.end_pid = last_vm_area.end_pid;
	last_fast_tier_scan.end_addr = last_vm_area.end_addr;

	return heat_map_size(&ctx->fast_tier_pages);
}

/**
 * returns number of pages found if success, 0 if error occurs
 **/
int mem_walk(struct pte_callback_context_t *ctx, const int n, const int mode)
{
	pte_entry_handler_t pte_handler;
	ctx->n_found = 0;
	ctx->n_to_find = n;

	heat_map_clear(&ctx->fast_tier_pages);
	heat_map_clear(&ctx->slow_tier_pages);

	pte_handler = page_scan_callback;
	do_ambix_page_walk(pte_handler, ctx);

	pr_info("found %d cold pages in dram \n",
		heat_map_size(&ctx->fast_tier_pages));
	pr_info("found %d hot pages in optane \n",
		heat_map_size(&ctx->slow_tier_pages));
	u32 slow_tier_hotter_pages =
		heat_map_compare(&ctx->slow_tier_pages, &ctx->fast_tier_pages);

	int demoted = 0;
	int promoted = 0;

	int ram_usage = get_real_memory_usage_per(DRAM_POOL);

	if (ram_usage > DRAM_MEM_USAGE_TARGET_PERCENT &&
	    heat_map_size(&ctx->fast_tier_pages)) {
		demoted += do_migration(
			&ctx->fast_tier_pages,
			min(MAX_N_FIND, heat_map_size(&ctx->fast_tier_pages)),
			NVRAM_POOL, COLDER_PAGES_FIRST);
	}

	if (ram_usage < DRAM_MEM_USAGE_TARGET_PERCENT &&
	    heat_map_size(&ctx->slow_tier_pages)) {
		promoted += do_migration(
			&ctx->slow_tier_pages,
			min(MAX_N_FIND, heat_map_size(&ctx->slow_tier_pages)),
			DRAM_POOL, WARMER_PAGES_FIRST);
	}

	if (ram_usage == DRAM_MEM_USAGE_TARGET_PERCENT &&
	    slow_tier_hotter_pages > 0) {
		demoted += do_migration(&ctx->fast_tier_pages,
					min(MAX_N_FIND, slow_tier_hotter_pages),
					NVRAM_POOL, COLDER_PAGES_FIRST);

		promoted +=
			do_migration(&ctx->slow_tier_pages,
				     min(MAX_N_FIND, slow_tier_hotter_pages),
				     DRAM_POOL, WARMER_PAGES_FIRST);
	}

	pr_info("Promoted: %d, Demoted: %d\n", promoted, demoted);

	return 1;
}

// MAIN ENTRY POINT
int ambix_check_memory(void)
{
	u32 n_migrated = 0;
	struct pte_callback_context_t *ctx = &g_context;

	pr_info("Memory management routine\n");

	//u64 track_start = tsc_rd();

	//pr_info("Tracking time: %lu\n", tsc_to_usec(tsc_rd() - track_start));

	mutex_lock(&bound_list_mutex);

	refresh_bound_programs();

	if (list_empty(&bound_program_list)) {
		pr_info("No bound processes...\n");
		mutex_unlock(&bound_list_mutex);

		goto release_return_acm;
	}

	mutex_unlock(&bound_list_mutex);

	/*pr_info("Ambix DRAM Usage: %d\n", get_memory_usage_percent(DRAM_POOL));
	pr_info("Ambix NVRAM Usage: %d\n",
		get_memory_usage_percent(NVRAM_POOL));

	pr_info("System DRAM Usage: %d\n",
		get_real_memory_usage_per(DRAM_POOL));
	pr_info("System NVRAM Usage: %d\n",
		get_real_memory_usage_per(NVRAM_POOL));*/

	mem_walk(ctx, MAX_N_FIND, 1);

release_return_acm:
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
