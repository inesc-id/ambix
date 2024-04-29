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

LIST_HEAD(bound_program_list);
DEFINE_MUTEX(bound_list_mutex);

bool create_pid_entry(int pid, int migrations_enabled)
{
	struct bound_program_t *new_bound_program, *entry;
	struct pid *pid_p = NULL;

	pid_p = find_get_pid(pid);

	new_bound_program = kmalloc(sizeof(struct bound_program_t), GFP_KERNEL);

	if (!new_bound_program) {
		printk(KERN_WARNING
		       "Failed to allocate memory for pid_entry\n");
		return false; // Return indicating failure
	}

	// Initialize the new PID entry
	new_bound_program->__pid = pid_p;
	new_bound_program->migrations_enabled = migrations_enabled;
	new_bound_program->fast_tier_bytes = 0;
	new_bound_program->slow_tier_bytes = 0;
	INIT_LIST_HEAD(&new_bound_program->memory_ranges);
	mutex_init(&new_bound_program->range_mutex);

	// Add the new PID entry to the global pid_list
	mutex_lock(&bound_list_mutex);

	// Check if PID already exists to avoid duplicates
	list_for_each_entry (entry, &bound_program_list, node) {
		if (pid_nr(entry->__pid) == pid) {
			printk(KERN_WARNING
			       "PID entry for %d already exists.\n",
			       pid);
			kfree(new_bound_program);
			mutex_unlock(&bound_list_mutex);
			return false;
		}
	}

	// Insert the new entry into the global list
	list_add_tail(&new_bound_program->node, &bound_program_list);

	mutex_unlock(&bound_list_mutex);

	printk(KERN_INFO "PID entry for %d created successfully.\n", pid);
	return true;
}

void remove_pid_entry(int pid)
{
	struct bound_program_t *pid_entry, *tmp_pid_entry;
	struct memory_range_t *range, *tmp_range;

	mutex_lock(&bound_list_mutex);

	list_for_each_entry_safe (pid_entry, tmp_pid_entry, &bound_program_list,
				  node) {
		if (pid_nr(pid_entry->__pid) == pid) {
			list_for_each_entry_safe (range, tmp_range,
						  &pid_entry->memory_ranges,
						  node) {
				char filename[128];
				snprintf(filename, 128, "%d.%lu", pid,
					 range->start_addr);
				remove_proc_entry(filename, proc_dir);

				list_del(&range->node);
				kfree(range);
			}

			put_pid(pid_entry->__pid);

			list_del(&pid_entry->node);
			kfree(pid_entry);

			printk(KERN_INFO
			       "PID entry and its memory ranges removed for PID %d.\n",
			       pid);
			break;
		}
	}

	mutex_unlock(&bound_list_mutex);
}

//! Caller should have mutex_lock(&pid_list_mutex)
void refresh_bound_programs(void)
{
	struct bound_program_t *bound_program, *tmp_bound_program_t;
	struct memory_range_t *range, *tmp_range;

	list_for_each_entry_safe (bound_program, tmp_bound_program_t,
				  &bound_program_list, node) {
		struct task_struct *t =
			get_pid_task(bound_program->__pid, PIDTYPE_PID);
		if (t) {
			put_task_struct(t);
			continue;
		}

		list_for_each_entry_safe (range, tmp_range,
					  &bound_program->memory_ranges, node) {
			char filename[128];
			snprintf(filename, 128, "%d.%lu",
				 pid_nr(bound_program->__pid),
				 range->start_addr);
			remove_proc_entry(filename, proc_dir);

			list_del(&range->node);
			kfree(range);
		}

		put_pid(bound_program->__pid);

		list_del(&bound_program->node);
		kfree(bound_program);

		printk(KERN_INFO
		       "PID entry and its memory ranges removed for PID %d.\n",
		       pid_nr(bound_program->__pid));
		break;
	}
}

int add_memory_range(int pid, unsigned long start_addr, unsigned long end_addr,
		     unsigned long allocation_site,
		     unsigned long total_size_bytes)
{
	struct bound_program_t *pid_entry = NULL;
	struct memory_range_t *new_range, *range, *temp_range = NULL;
	bool pid_found = false;

	new_range = kmalloc(sizeof(struct memory_range_t), GFP_KERNEL);
	if (!new_range) {
		pr_info("Failed to allocate memory for memory range\n");
		return 0;
	}

	new_range->start_addr = start_addr;
	new_range->end_addr = end_addr;
	new_range->total_size_bytes = total_size_bytes;
	new_range->fast_tier_bytes = 0;
	new_range->slow_tier_bytes = 0;
	new_range->allocation_site = allocation_site;
	new_range->migrate_pages = 1;

	//INIT_LIST_HEAD(&new_range->node);

	mutex_lock(&bound_list_mutex);

	// Check if PID exists and find ordered insertion point
	list_for_each_entry (pid_entry, &bound_program_list, node) {
		if (pid_nr(pid_entry->__pid) == pid) {
			pid_found = true;
			list_for_each_entry_safe (range, temp_range,
						  &pid_entry->memory_ranges,
						  node) {
				/* Address already registered*/
				if (start_addr == range->start_addr) {
					kfree(new_range);
					mutex_unlock(&bound_list_mutex);
					return 0;
				}

				if (start_addr < range->start_addr) {
					list_add_tail(&new_range->node,
						      &range->node);
					create_proc_file(pid, start_addr);
					goto inserted;
				}
			}

			create_proc_file(pid, start_addr);
			list_add_tail(&new_range->node,
				      &pid_entry->memory_ranges);

			break;
		}
	}

inserted:

	mutex_unlock(&bound_list_mutex);

	if (pid_found) {
		list_for_each_entry_safe (range, temp_range,
					  &pid_entry->memory_ranges, node) {
			/* Address already registered*/
			pr_info("start: %lu, \n", range->start_addr);
			
		}
	}

	if (!pid_found) {
		kfree(new_range);
		pr_info("PID %d not bound to Ambix.\n", pid);
		return 0;
	}
	return 1;
}

void remove_memory_range(int pid, unsigned long start_addr,
			 unsigned long end_addr)
{
	struct bound_program_t *pid_entry;
	struct memory_range_t *range, *tmp;

	mutex_lock(&bound_list_mutex);

	list_for_each_entry (pid_entry, &bound_program_list, node) {
		if (pid_nr(pid_entry->__pid) == pid) {
			list_for_each_entry_safe (
				range, tmp, &pid_entry->memory_ranges, node) {
				if (range->start_addr == start_addr &&
				    range->end_addr == end_addr) {
					char filename[128];
					snprintf(filename, 128, "%d.%lu", pid,
						 range->start_addr);
					remove_proc_entry(filename, proc_dir);

					list_del(&range->node);
					kfree(range);
					break; // Assuming no duplicate ranges for a PID
				}
			}
			break;
		}
	}

	mutex_unlock(&bound_list_mutex);
}

//! Caller should have mutex_lock(&pid_list_mutex)
struct memory_range_t *find_memory_range_for_address(int pid,
						     unsigned long address)
{
	struct bound_program_t *pid_entry;
	struct memory_range_t *range;

	list_for_each_entry (pid_entry, &bound_program_list, node) {
		if (pid_nr(pid_entry->__pid) == pid) {
			list_for_each_entry (range, &pid_entry->memory_ranges,
					     node) {
				if (address >= range->start_addr &&
				    address < range->end_addr) {
					mutex_unlock(&pid_entry->range_mutex);
					return range;
				}
				if (address < range->start_addr) {
					return range;
				}
			}
			break;
		}
	}

	return NULL; // Return NULL or the next closest range.
}
