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

#include "ambix_types.h"
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/sysinfo.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/rwlock.h>
#include <linux/proc_fs.h>

#include "config.h"
#include "sys_mem_info.h"
#include "kernel_symbols.h"
#include "vm_management.h"
#include "migrate.h"

DEFINE_MUTEX(USAGE_mtx);

// Node definition: DRAM nodes' (memory mode) ids must always be a lower value
// than NVRAM nodes' ids due to the memory policy set in client-placement.c
// CHANGE THIS ACCORDING TO HARDWARE CONFIGURATION
const int DRAM_NODES[] = _DRAM_NODES;
const int NVRAM_NODES[] = _NVRAM_NODES;

const int n_dram_nodes = ARRAY_SIZE(DRAM_NODES);
const int n_nvram_nodes = ARRAY_SIZE(NVRAM_NODES);

unsigned long long ambix_dram_usage = 0;
unsigned long long ambix_nvram_usage = 0;

unsigned long long total_dram_usage = 0;
unsigned long long total_nvram_usage = 0;

struct proc_dir_entry *proc_dir;

static int vm_area_mem_info_show(struct seq_file *s, void *private)
{
	char *filename = s->file->f_path.dentry->d_iname;
	int pid;
	unsigned long start_addr;
	struct memory_range_t *vm_area;

	sscanf(filename, "%d.%lu", &pid, &start_addr);

	mutex_lock(&bound_list_mutex);


	vm_area = find_memory_range_for_address(pid, start_addr);

	if (!vm_area) {
		seq_printf(
			s,
			"fast_tier_usage, slow_tier_usage, allocation_site\n-1, -1, -1\n");

		mutex_unlock(&bound_list_mutex);

		return 0;
	}


	/*if (vm_area->start_addr != start_addr) {
		seq_printf(
			s,
			"fast_tier_usage, slow_tier_usage, allocation_site\n%lu, %lu, 0\n", vm_area->start_addr, start_addr);

		mutex_unlock(&bound_list_mutex);

		return 0;
	}*/

	seq_printf(
		s,
		"fast_tier_usage, slow_tier_usage, allocation_site\n%lu, %lu, %lu\n",
		vm_area->fast_tier_bytes, vm_area->slow_tier_bytes,
		vm_area->allocation_site);

	mutex_unlock(&bound_list_mutex);

	return 0;
}

static int vm_area_proc_open(struct inode *node, struct file *file)
{
	return single_open(file, vm_area_mem_info_show, NULL);
}

static const struct proc_ops kmod_proc_ops = {
	.proc_open = vm_area_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int create_proc_file(int pid, unsigned long start_addr)
{
	char filename[128];
	struct proc_dir_entry *entry;
	// ! check function return
	snprintf(filename, 128, "%d.%lu", pid, start_addr);

	entry = proc_create(filename, 0666, proc_dir, &kmod_proc_ops);

	if (!entry) {
		return -ENOMEM;
	}

	return 0;
}

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
		totalram += inf.totalram * inf.mem_unit;
		freeram += inf.freeram * inf.mem_unit;
	}

	// integer division so we need to scale the values so the quotient != 0
	return ((totalram - freeram) * 100) / totalram;
}

// returns used memory for pool in KiB (times the usage factor)
// K(totalram - freeram) / K(totalram) is between [0, 1]
// by multiplying by USAGE_FACTOR we can decrease the ratio above
// e.g. reduced DRAM from 8GiB to 4GiB, returns how many KiB of these 4GiB are
// being used
u32 get_memory_usage_percent(enum pool_t pool)
{
	int i = 0;
	u64 totalram = 0, usedram = 0;
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
		totalram += inf.totalram * inf.mem_unit;
		// freeram += inf.freeram;
	}

	mutex_lock(&bound_list_mutex);


	if (pool == DRAM_POOL) {
		usedram = ambix_dram_usage;
	} else {
		usedram = ambix_nvram_usage;
	}
	mutex_unlock(&bound_list_mutex);


	// pr_info("K(totalram) - freeram = %llu", (K(totalram) - freeram));
	// pr_info("((K(totalram) - freeram) * 100 / K(totalram)) = %llu",
	// ((K(totalram) - freeram) * 100 / K(totalram)));

	// integer division so we need to scale the values so the quotient != 0
	if (ratio == 0)
		return 0;

	return ((usedram * 100) / (totalram)) * (100 / ratio);
}

unsigned long long get_memory_usage_bytes(enum pool_t pool)
{
	unsigned long long usedmem;
	mutex_lock(&bound_list_mutex);


	if (pool == DRAM_POOL) {
		usedmem = total_dram_usage;
	} else {
		usedmem = total_nvram_usage;
	}
	mutex_unlock(&bound_list_mutex);


	return usedmem;
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
