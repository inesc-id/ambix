/**
 * @file    sys_mem_info.c
 * @author  INESC-ID
 * @date    23 oct 2023
 * @version 1.0.0
 * @brief  Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code provided by reza
 * karimi <r68karimi@gmail.com>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/sysinfo.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/mm.h>

#include "config.h"
#include "sys_mem_info.h"
#include "kernel_symbols.h"
#include "vm_management.h"

DEFINE_MUTEX(USAGE_mtx);

// Node definition: DRAM nodes' (memory mode) ids must always be a lower value
// than NVRAM nodes' ids due to the memory policy set in client-placement.c
// CHANGE THIS ACCORDING TO HARDWARE CONFIGURATION
const int DRAM_NODES[] = _DRAM_NODES;
const int NVRAM_NODES[] = _NVRAM_NODES;

const int n_dram_nodes = ARRAY_SIZE(DRAM_NODES);
const int n_nvram_nodes = ARRAY_SIZE(NVRAM_NODES);

static unsigned long long dram_usage = 0;
static unsigned long long nvram_usage = 0;

static unsigned long long total_dram_usage = 0;
static unsigned long long total_nvram_usage = 0;

int is_page_in_pool(pte_t pte_t, enum pool_t pool)
{
	const int *nodes;
	int pool_size, i;
	int nid = pfn_to_nid(pte_pfn(pte_t));

	if (pool == DRAM_POOL) {
		nodes = DRAM_NODES;
		pool_size = n_dram_nodes;
	} else {
		nodes = NVRAM_NODES;
		pool_size = n_nvram_nodes;
	}
	for (i = 0; i < pool_size; i++) {
		if (nodes[i] == nid) {
			return 1;
		}
	}
	return 0;
}

static int pte_callback_usage(pte_t *ptep, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	if (!pte_present(*ptep))
		return 0;

	if (is_page_in_pool(*ptep, DRAM_POOL)) {
		dram_usage += PAGE_SIZE;
	} else if (is_page_in_pool(*ptep, NVRAM_POOL)) {
		nvram_usage += PAGE_SIZE;
	}

	return 0;
}

void walk_ranges_usage(void)
{
	struct task_struct *t = NULL;
	struct mm_walk_ops mem_walk_ops = { .pte_entry = pte_callback_usage };
	struct mm_struct *mm = NULL;
	struct vm_area_t *current_vm;
	struct hlist_node *tmp;
	unsigned int bkt;

	total_dram_usage = 0;
	total_nvram_usage = 0;

	pr_info("Walking page ranges to get memory usage");

	mutex_lock(&VM_AREAS_LOCK);

	hash_for_each_safe (AMBIX_VM_AREAS, bkt, tmp, current_vm, node) {
		t = get_pid_task(current_vm->__pid, PIDTYPE_PID);
		if (!t) {
			pr_warn("Can't resolve task (%d).\n",
				pid_nr(current_vm->__pid));
			continue;
		}
		mm = get_task_mm(t);
		if (!mm) {
			pr_warn("Can't resolve mm_struct of task (%d)",
				pid_nr(current_vm->__pid));
			put_task_struct(t);
			continue;
		}

		dram_usage = 0;
		nvram_usage = 0;

		mmap_read_lock(mm);
		g_walk_page_range(mm, current_vm->start_addr, current_vm->end_addr,
				  &mem_walk_ops, NULL);
		mmap_read_unlock(mm);

		current_vm->fast_tier_bytes = dram_usage;
		current_vm->slow_tier_bytes = nvram_usage;

		pr_info("{PID: %d, Start Addr: %lx, End Addr: %lx, Allocation Site: %lx, "
			"Total Size Bytes: %lu, Fast Tier Bytes: %lu, Slow Tier Bytes: %lu}\n",
			pid_vnr(current_vm->__pid), current_vm->start_addr,
			current_vm->end_addr, current_vm->allocation_site,
			current_vm->total_size_bytes, current_vm->fast_tier_bytes,
			current_vm->slow_tier_bytes);

		total_dram_usage += dram_usage;
		total_nvram_usage += nvram_usage;

		mmput(mm);
		mm = NULL;
		put_task_struct(t);
		t = NULL;
	}
	mutex_unlock(&USAGE_mtx);
}

// page count to KiB
const int *get_pool_nodes(const enum pool_t pool)
{
	switch (pool) {
	case DRAM_POOL:
		return DRAM_NODES;
	case NVRAM_POOL:
		return NVRAM_NODES;
	}

	pr_err("Unknown pool %d\n", pool);
	return ERR_PTR(-EINVAL);
}

size_t get_pool_size(const enum pool_t pool)
{
	switch (pool) {
	case DRAM_POOL:
		return n_dram_nodes;
	case NVRAM_POOL:
		return n_nvram_nodes;
	}

	pr_err("Unknown pool %d\n", pool);
	return 0;
}

const char *get_pool_name(const enum pool_t pool)
{
	switch (pool) {
	case DRAM_POOL:
		return "DRAM";
	case NVRAM_POOL:
		return "NVRAM";
	default:
		return "Unknown";
	}
}

u32 get_real_memory_usage_per(enum pool_t pool)
{
	int i = 0;
	u64 totalram = 0, freeram = 0;
	const int *nodes = get_pool_nodes(pool);
	size_t size = get_pool_size(pool);
	if (IS_ERR(nodes) || size == 0)
		return 0;
	for (i = 0; i < size; ++i) {
		struct sysinfo inf;
		g_si_meminfo_node(&inf, nodes[i]);
		totalram += inf.totalram;
		freeram += inf.freeram;
	}

	// integer division so we need to scale the values so the quotient != 0
	return (K(totalram - freeram) * 100 / K(totalram));
}

// returns used memory for pool in KiB (times the usage factor)
// K(totalram - freeram) / K(totalram) is between [0, 1]
// by multiplying by USAGE_FACTOR we can decrease the ratio above
// e.g. reduced DRAM from 8GiB to 4GiB, returns how many KiB of these 4GiB are
// being used
u32 get_memory_usage_percent(enum pool_t pool)
{
	int i = 0;
	u64 totalram = 0, freeram = 0;
	const int *nodes = get_pool_nodes(pool);
	size_t size = get_pool_size(pool);
	u32 ratio;
	if (pool == DRAM_POOL) {
		ratio = DRAM_MEM_USAGE_RATIO;
	} else {
		ratio = NVRAM_MEM_USAGE_RATIO;
	}
	if (IS_ERR(nodes) || size == 0)
		return 0;
	for (i = 0; i < size; ++i) {
		struct sysinfo inf;
		g_si_meminfo_node(&inf, nodes[i]);
		totalram += inf.totalram;
		// freeram += inf.freeram;
	}

	mutex_lock(&USAGE_mtx);
	if (pool == DRAM_POOL) {
		freeram = K(totalram) - dram_usage;
	} else {
		freeram = K(totalram) - nvram_usage;
	}
	mutex_unlock(&USAGE_mtx);

	// pr_info("K(totalram) - freeram = %llu", (K(totalram) - freeram));
	// pr_info("((K(totalram) - freeram) * 100 / K(totalram)) = %llu",
	// ((K(totalram) - freeram) * 100 / K(totalram)));

	// integer division so we need to scale the values so the quotient != 0
	return ((K(totalram) - freeram) * 100 / K(totalram)) * 100 / ratio;
}

// number of bytes in total for pool (after being reduced with a certain ratio)
u64 get_memory_total_ratio(enum pool_t pool)
{
	int i = 0;
	u64 totalram = 0;
	const int *nodes = get_pool_nodes(pool);
	const size_t size = get_pool_size(pool);
	u64 ratio;
	if (pool == DRAM_POOL) {
		ratio = DRAM_MEM_USAGE_RATIO;
	} else {
		ratio = NVRAM_MEM_USAGE_RATIO;
	}
	if (IS_ERR(nodes) || size == 0)
		return 0;
	for (i = 0; i < size; ++i) {
		struct sysinfo inf;
		g_si_meminfo_node(&inf, nodes[i]);
		totalram += inf.totalram;
	}

	return totalram * PAGE_SIZE * ratio / 100;
}

u64 get_memory_total(enum pool_t pool)
{
	int i = 0;
	u64 totalram = 0;
	const int *nodes = get_pool_nodes(pool);
	const size_t size = get_pool_size(pool);
	if (IS_ERR(nodes) || size == 0)
		return 0;
	for (i = 0; i < size; ++i) {
		struct sysinfo inf;
		g_si_meminfo_node(&inf, nodes[i]);
		totalram += inf.totalram;
	}

	return totalram * PAGE_SIZE;
}
