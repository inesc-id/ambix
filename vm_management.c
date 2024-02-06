/**
 * @file    vm_management.c
 * @author  INESC-ID
 * @date    23 oct 2023
 * @version 1.0.0
 * @brief  Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code provided by reza
 * karimi <r68karimi@gmail.com>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/proc_fs.h> /* Necessary because we use the proc fs */

#include "sys_mem_info.h"
#include "vm_management.h"

DEFINE_RWLOCK(my_rwlock);

LIST_HEAD(AMBIX_VM_AREAS);

int ambix_bind_pid_constrained(const pid_t pid, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size, int migrate_pages)
{
	struct pid *pid_p = NULL;
	struct vm_area_t *current_vm;
	int rc = 0;

	pid_p = find_get_pid(pid);
	if (!pid_p) {
		pr_warn("Invalid pid value (%d): can't find pid.\n", pid);
		rc = -1;
		goto out;
	}

	write_lock(&my_rwlock);

	list_for_each_entry (current_vm, &AMBIX_VM_AREAS, node) {
		if (pid_nr(current_vm->__pid) == pid) {
			if (current_vm->start_addr == start_addr &&
			    current_vm->end_addr == end_addr) {
				pr_info("Already managing given vm range.\n");
				rc = -1;
				goto out_unlock_put;
			}

			if (current_vm->end_addr == MAX_ADDRESS) {
				pr_info("Already entire process vm range.\n");
				rc = -1;
				goto out_unlock_put;
			}
		}
	}

	struct vm_area_t *new_area = kmalloc(sizeof(*new_area), GFP_KERNEL);

	if (!new_area) {
		pr_info("Failed to allocate memory for new vm_area\n");
		rc = -1;
		goto out_unlock_put;
	}

	new_area->__pid = pid_p;
	new_area->start_addr = start_addr;
	new_area->end_addr = end_addr;
	new_area->total_size_bytes = size;
	new_area->fast_tier_bytes = 0;
	new_area->slow_tier_bytes = 0;
	new_area->allocation_site = allocation_site;
	new_area->migrate_pages = migrate_pages;

	// Insert in order
	struct vm_area_t *current_area;
	list_for_each_entry (current_area, &AMBIX_VM_AREAS, node) {
		if (pid < pid_nr(current_area->__pid)) {
			list_add_tail(&new_area->node, &current_area->node);
			goto inserted;
		} else if (pid > pid_nr(current_area->__pid)) {
			continue;
		} else if (current_area->start_addr > new_area->start_addr) {
			list_add_tail(&new_area->node, &current_area->node);
			goto inserted;
		}
	}
	list_add_tail(&new_area->node, &AMBIX_VM_AREAS);

inserted:
	pr_info("Bound pid=%d with start_addr=%lx and end_addr=%lx.\n", pid,
		start_addr, end_addr);

	create_proc_file(pid_nr(new_area->__pid), new_area->start_addr);

out_unlock_put:

	if (rc == -1)
		put_pid(pid_p);

	write_unlock(&my_rwlock);

out:
	return rc;
}

int ambix_bind_pid(const pid_t nr)
{
	return ambix_bind_pid_constrained(nr, 0, MAX_ADDRESS, 0, 0, 1);
}

int ambix_unbind_pid(const pid_t pid)
{
	struct vm_area_t *current_vm, *tmp;

	write_lock(&my_rwlock);

	list_for_each_entry_safe (current_vm, tmp, &AMBIX_VM_AREAS, node) {
		if (pid_nr(current_vm->__pid) == pid) {
			pr_info("Unbound pid=%d, start_addr=%lu, start_addr=%lu. \n",
				pid, current_vm->start_addr,
				current_vm->end_addr);

			put_pid(current_vm->__pid);
			list_del(&current_vm->node);
			if (!current_vm->migrate_pages) {
				char filename[128];
				snprintf(filename, 128, "%d.%lu",
					 pid_nr(current_vm->__pid),
					 current_vm->start_addr);
				remove_proc_entry(filename, proc_dir);
			}

			kfree(current_vm);
		}
	}

	write_unlock(&my_rwlock);

	return 0;
}

int ambix_unbind_range_pid(const pid_t pid, unsigned long start,
			   unsigned long end)
{
	struct vm_area_t *current_vm, *tmp;

	write_lock(&my_rwlock);

	list_for_each_entry_safe (current_vm, tmp, &AMBIX_VM_AREAS, node) {
		if (pid_nr(current_vm->__pid) == pid &&
		    start == current_vm->start_addr &&
		    end == current_vm->end_addr) {
			put_pid(current_vm->__pid);

			list_del(&current_vm->node);

			if (!current_vm->migrate_pages) {
				char filename[128];
				snprintf(filename, 128, "%d.%lu",
					 pid_nr(current_vm->__pid),
					 current_vm->start_addr);
				remove_proc_entry(filename, proc_dir);
			}

			kfree(current_vm);

			pr_info("Unbound pid=%d, start_addr=%lu, start_addr=%lu. \n",
				pid, start, end);
			break;
		}
	}

	write_unlock(&my_rwlock);

	return 0;
}

void refresh_bound_vm_areas(void)
{
	struct vm_area_t *current_vm, *tmp;

	write_lock(&my_rwlock);

	list_for_each_entry_safe (current_vm, tmp, &AMBIX_VM_AREAS, node) {
		struct task_struct *t =
			get_pid_task(current_vm->__pid, PIDTYPE_PID);
		if (t) {
			put_task_struct(t);
			continue;
		}

		pr_info("Process %d unbound from ambix.\n",
			pid_nr(current_vm->__pid));

		if (!current_vm->migrate_pages) {
			char filename[128];
			snprintf(filename, 128, "%d.%lu",
				 pid_nr(current_vm->__pid),
				 current_vm->start_addr);
			remove_proc_entry(filename, proc_dir);
		}

		put_pid(current_vm->__pid);
		list_del(&current_vm->node);
		kfree(current_vm);
	}

	write_unlock(&my_rwlock);
}

//! Should be called holding read_lock(&my_rwlock);
struct vm_area_t *ambix_get_vm_area(int pid, unsigned long addr)
{
	struct vm_area_t *current_vm;

	list_for_each_entry (current_vm, &AMBIX_VM_AREAS, node) {
		if (pid_nr(current_vm->__pid) == pid &&
		    current_vm->start_addr <= addr &&
		    current_vm->end_addr >= addr) {
			return current_vm;
		}
	}

	return NULL; // Return NULL if not found
}
