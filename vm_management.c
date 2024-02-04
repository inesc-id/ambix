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

#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "vm_management.h"

DEFINE_MUTEX(VM_AREAS_LOCK);

//! Hash table size should be user definable 
DEFINE_HASHTABLE(AMBIX_VM_AREAS, 7);

int ambix_bind_pid_constrained(const pid_t pid, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size)
{
	struct pid *pid_p = NULL;
	struct vm_area_t *current_vm;
	unsigned int bkt;
	int rc = 0;

	pid_p = find_get_pid(pid);
	if (!pid_p) {
		pr_warn("Invalid pid value (%d): can't find pid.\n", pid);
		rc = -1;
		goto out;
	}

	mutex_lock(&VM_AREAS_LOCK);

	hash_for_each (AMBIX_VM_AREAS, bkt, current_vm, node) {
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
		goto out_unlock_put;
	}

	new_area->__pid = pid_p;
	new_area->start_addr = start_addr;
	new_area->end_addr = end_addr;
	new_area->total_size_bytes = size;
	new_area->fast_tier_bytes = 0;
	new_area->slow_tier_bytes = 0;

	if(allocation_site == 0){
		new_area->allocation_site = pid_nr(pid_p);
	}

	hash_add(AMBIX_VM_AREAS, &new_area->node, new_area->allocation_site);

	pr_info("Bound pid=%d with start_addr=%lx and end_addr=%lx.\n", pid,
		start_addr, end_addr);

out_unlock_put:

	if (rc == -1)
		put_pid(pid_p);

	mutex_unlock(&VM_AREAS_LOCK);

out:
	return rc;
}

int ambix_bind_pid(const pid_t nr)
{
	return ambix_bind_pid_constrained(nr, 0, MAX_ADDRESS, 0, 0);
}

int ambix_unbind_pid(const pid_t pid)
{
	struct vm_area_t *current_vm;
	struct hlist_node *tmp;
	unsigned int bkt;

	mutex_lock(&VM_AREAS_LOCK);

	hash_for_each_safe (AMBIX_VM_AREAS, bkt, tmp, current_vm, node) {
		if (pid_nr(current_vm->__pid) == pid) {
			pr_info("Unbound pid=%d, start_addr=%lu, start_addr=%lu. \n",
				pid, current_vm->start_addr, current_vm->end_addr);

			put_pid(current_vm->__pid);

			hash_del(&current_vm->node);
			kfree(current_vm);

			break;
		}
	}

	mutex_unlock(&VM_AREAS_LOCK);

	return 0;
}

int ambix_unbind_range_pid(const pid_t pid, unsigned long start,
			   unsigned long end)
{
	struct vm_area_t *current_vm;
	struct hlist_node *tmp;
	unsigned int bkt;

	mutex_lock(&VM_AREAS_LOCK);

	hash_for_each_safe (AMBIX_VM_AREAS, bkt, tmp, current_vm, node) {
		if (pid_nr(current_vm->__pid) == pid &&
		    start == current_vm->start_addr && end == current_vm->end_addr) {
			put_pid(current_vm->__pid);

			hash_del(&current_vm->node);
			kfree(current_vm);

			pr_info("Unbound pid=%d, start_addr=%lu, start_addr=%lu. \n",
				pid, start, end);
			break;
		}
	}

	mutex_unlock(&VM_AREAS_LOCK);

	return 0;
}

// NB! should be called under VM_AREAS_LOCK lock
void refresh_bound_vm_areas(void)
{
	struct vm_area_t *current_vm;
	struct hlist_node *tmp;
	unsigned int bkt;

	hash_for_each_safe (AMBIX_VM_AREAS, bkt, tmp, current_vm, node) {
		struct task_struct *t =
			get_pid_task(current_vm->__pid, PIDTYPE_PID);
		if (t) {
			put_task_struct(t);
			continue;
		}

		pr_info("Process %d has gone.\n", pid_nr(current_vm->__pid));

		put_pid(current_vm->__pid);
		hash_del(&current_vm->node);
		kfree(current_vm);
	}
}

// NB! should be called under VM_AREAS_LOCK lock
struct vm_area_t * ambix_get_vm_area(unsigned long allocation_site){

	struct vm_area_t *current_vm, *ret = NULL;

	hash_for_each_possible(AMBIX_VM_AREAS, current_vm, node, allocation_site) {
        // Check the name.
        if (current_vm->allocation_site == allocation_site) {
			ret = current_vm;
            break;
        }
    }

	return ret;
}