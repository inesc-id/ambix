#ifndef VM_MANAGEMENT_H
#define VM_MANAGEMENT_H

#include <linux/rwlock.h>

#define IS_64BIT (sizeof(void *) == 8)
#define MAX_ADDRESS                                                            \
	(IS_64BIT ?                                                            \
		 0xFFFF880000000000UL :                                        \
		 0xC0000000UL) // Max user-space addresses for the x86 architecture

struct bound_program_t {
	struct pid *__pid;
	struct list_head memory_ranges;
	struct mutex range_mutex;
	struct list_head node;
	unsigned long fast_tier_bytes;
	unsigned long slow_tier_bytes;
	int migrations_enabled;
};

struct memory_range_t {
	struct list_head node;
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long allocation_site;
	unsigned long total_size_bytes;
	unsigned long fast_tier_bytes;
	unsigned long slow_tier_bytes;
	int migrate_pages;
};

struct vm_area_walk_t {
	int start_pid;
	unsigned long start_addr;
	int end_pid;
	unsigned long end_addr;
};



extern struct list_head bound_program_list;
extern struct mutex bound_list_mutex;


bool create_pid_entry(int pid, int migrations_enabled);

void remove_pid_entry(int pid);

//! Caller should have mutex_lock(&pid_list_mutex)
void refresh_bound_programs(void);

int add_memory_range(int pid, unsigned long start_addr, unsigned long end_addr,
		     unsigned long allocation_site,
		     unsigned long total_size_bytes);

void remove_memory_range(int pid, unsigned long start_addr,
			 unsigned long end_addr);

//! Caller should have mutex_lock(&pid_list_mutex)
struct memory_range_t *find_memory_range_for_address(int pid,
						   unsigned long address);

#endif // VM_MANAGEMENT_H
