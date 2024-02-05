#ifndef VM_MANAGEMENT_H
#define VM_MANAGEMENT_H

#include <linux/rwlock.h>

#define IS_64BIT (sizeof(void *) == 8)
#define MAX_ADDRESS                                                            \
	(IS_64BIT ?                                                            \
		 0xFFFF880000000000UL :                                        \
		 0xC0000000UL) // Max user-space addresses for the x86 architecture

struct vm_area_t {
	struct list_head node;
	struct pid *__pid;
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

extern struct list_head AMBIX_VM_AREAS;
extern rwlock_t my_rwlock;

int ambix_bind_pid_constrained(const pid_t pid, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size, int migrate_pages);

int ambix_bind_pid(const pid_t nr);

int ambix_unbind_pid(const pid_t nr);

int ambix_unbind_range_pid(const pid_t nr, unsigned long start,
			   unsigned long end);

void refresh_bound_vm_areas(void);

struct vm_area_t *ambix_get_vm_area(int pid, unsigned long addr);

#endif // VM_MANAGEMENT_H
