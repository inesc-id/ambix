/**
 * @file    migrate.c
 * @author  INESC-ID
 * @date    23 oct 2023
 * @version 1.0.0
 * @brief  Intended for the 5.10.0 linux kernel. Adapted from the code prov
 * ided by ilia kuzmin <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the 
 * code provided by reza karimi <r68karimi@gmail.com>, adapted from the code
 * implemented by miguel marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/migrate.h>
#include <linux/huge_mm.h>
#include <linux/mempolicy.h>
#include <linux/mmzone.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/atomic.h>
#include <linux/list.h>

#include "config.h"
#include "kernel_symbols.h"
#include "migrate.h"
#include "vm_management.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 5)
/**
 * Can't import inline functions, have to duplicate:
 */
atomic_t *g_lru_disable_count;

static inline bool my_lru_cache_disable(void)
{
	return atomic_read(g_lru_disable_count);
}

static inline void my_lru_cache_enable(void)
{
	atomic_dec(g_lru_disable_count);
}
#else
static inline bool my_lru_cache_disable(void)
{
	g_lru_add_drain_all();
	return true;
}
static inline void my_lru_cache_enable(void)
{
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 6)
#define thp_nr_pages(head) hpage_nr_pages(head)
#endif

static struct page *alloc_dst_page(struct page *page, unsigned long data)
{
	int nid = (int)data;
	struct page *newpage;

	newpage = __alloc_pages_node(nid,
				     (GFP_HIGHUSER_MOVABLE | __GFP_THISNODE |
				      __GFP_NOMEMALLOC | __GFP_NORETRY |
				      __GFP_NOWARN) &
					     ~__GFP_RECLAIM,
				     0);

	return newpage;
}
/*
 * Resolves the given address to a struct page, isolates it from the LRU and
 * puts it to the given pagelist.
 * Returns:
 *     errno - if the page cannot be found/isolated
 *     0 - when it doesn't have to be migrated because it is already on the
 *         target node
 *     1 - when it has been queued
 */

static int add_page_for_migration(struct mm_struct *mm, unsigned long addr,
				  int node, struct list_head *pagelist)
{
	struct vm_area_struct *vma;
	struct page *page;
	unsigned int follflags;
	int err;

	mmap_read_lock(mm);
	err = -EFAULT;
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start || !g_vma_migratable(vma)) {
		pr_debug("Can not find vma.\n");
		goto out;
	}

	/* FOLL_DUMP to ignore special (like zero) pages */
	follflags = FOLL_GET | FOLL_DUMP;
	page = g_follow_page(vma, addr, follflags);

	err = PTR_ERR(page);
	if (IS_ERR(page)) {
		pr_debug("Can not follow page.\n");
		goto out;
	}

	err = -ENOENT;
	if (!page) {
		pr_debug("Page is empty.\n");
		goto out;
	}

	err = 0;
	if (page_to_nid(page) == node) {
		pr_debug("Page is already on desired node.\n");
		goto out_putpage;
	}

#ifdef DEBUG_MIGRATIONS
	unsigned long long ts = ktime_get_real_fast_ns();
	pr_info("0x%lx,%d,%d,%d,%llu", addr, page_to_nid(page), node,
		migration_type, ts);
#endif

	err = -EACCES;
	if (PageHuge(page)) {
		if (PageHead(page)) {
			g_isolate_huge_page(page, pagelist);
			err = 1;
		}
	} else {
		struct page *head;

		head = compound_head(page);
		err = g_isolate_lru_page(head);
		if (err) {
			pr_debug("Failed to isolate page.\n");
			goto out_putpage;
		}

		err = 1;
		list_add_tail(&head->lru, pagelist);
		mod_node_page_state(page_pgdat(head),
				    NR_ISOLATED_ANON + page_is_file_lru(head),
				    thp_nr_pages(head));
	}
out_putpage:
	/*
   * Either remove the duplicate refcount from
   * isolate_lru_page() or drop the page ref if it was
   * not isolated.
   */
	put_page(page);
out:
	mmap_read_unlock(mm);
	return err;
}

int kernel_migrate_pages(struct list_head *pagelist, int node)
{
	int err;

	if (list_empty(pagelist))
		return 0;

	err = g_migrate_pages(pagelist, alloc_dst_page, NULL,
			      (unsigned long)node, MIGRATE_SYNC, MR_SYSCALL);

	if (err) {
		g_putback_movable_pages(pagelist);
	}

	return err;
}

// Does migrations in batches per pid
int do_migration(struct vm_heat_map *heat_map, const size_t n_to_migrate,
		 const enum pool_t dst, int priority)
{
	LIST_HEAD(pagelist);
	size_t pages_migrated = 0;
	const int *node_list = get_pool_nodes(dst);
	// TODO: pick nodes dynamically
	int node = node_list[0];
	int err, rc = 0;
	unsigned long found_addr, addr;
	pid_t page_pid, last_page_pid = -1;
	struct pid *vm_area_pid;
	struct task_struct *t = NULL;
	struct mm_struct *mm = NULL;

	my_lru_cache_disable();

	if (node < 0 || node >= MAX_NUMNODES || !node_state(node, N_MEMORY)) {
		pr_err("Invalid node %d\n", node);
		rc = -1;
		goto out;
	}

	pr_debug("DO MIGRATION: %ld pages -> %s", n_to_migrate,
		 get_pool_name(dst));

	FREQ_ORDERED_TRAVERSE(heat_map, priority, found_addr, vm_area_pid)
	{
		if (pages_migrated >= n_to_migrate) {
			break;
		}

		addr = (unsigned long)untagged_addr(found_addr);
		page_pid = pid_nr(vm_area_pid);

		if (page_pid != last_page_pid && mm) {
			pages_migrated -= kernel_migrate_pages(&pagelist, node);

			mmput(mm);
			mm = NULL;
			put_task_struct(t);
			t = NULL;
		}

		if (!mm) {
			t = get_pid_task(vm_area_pid, PIDTYPE_PID);

			if (t == NULL) {
				pr_warn("Migration: Can't resolve struct of task (%d).\n",
					pid_nr(vm_area_pid));
				goto out;
			}

			mm = get_task_mm(t);

			if (mm == NULL) {
				pr_warn("Migration: Can't resolve mm_struct of task (%d).\n",
					pid_nr(vm_area_pid));
				goto out;
			}

			last_page_pid = page_pid;
		}

		err = add_page_for_migration(mm, addr, node, &pagelist);

		/*Page is successfully queued for migration*/
		if (err > 0) {
			pages_migrated++;
		}
	}

	pages_migrated -= kernel_migrate_pages(&pagelist, node);

	pr_info("Successfully migrated %ld\n", pages_migrated);

out:
	if (mm)
		mmput(mm);

	if (t)
		put_task_struct(t);

	my_lru_cache_enable();

	rc = pages_migrated;

	return rc;
}
