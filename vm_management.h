#ifndef VM_MANAGEMENT_H
#define VM_MANAGEMENT_H

#include <linux/hashtable.h>

// sets the number of virtual memory ranges that can be bound to Ambix at any given time
#define MAX_VM_AREAS 20

#define IS_64BIT (sizeof(void *) == 8)
#define MAX_ADDRESS                                                            \
	(IS_64BIT ?                                                            \
		 0xFFFF880000000000UL :                                        \
		 0xC0000000UL) // Max user-space addresses for the x86 architecture

struct vm_area_t {
	struct hlist_node node;
	struct pid *__pid;
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long allocation_site;
	unsigned long total_size_bytes;
	unsigned long fast_tier_bytes;
	unsigned long slow_tier_bytes;
};

#define HASH_ITERATE_CIRCULAR_ENDLESS(name, bkt, start_key, start_obj, current_vm)             \
	for (bkt = hash_min(start_key, HASH_BITS(name));;             \
	     bkt = (bkt + 1) % (1 << HASH_BITS(name)),                         \
		      start_obj = (&name[bkt])->first)                         \
		for (current_vm = hlist_entry_safe(start_obj, typeof(*(current_vm)), \
						node);                         \
		     current_vm;                                                  \
		     current_vm = hlist_entry_safe((current_vm)->node.next,        \
						typeof(*(current_vm)), node))

#define AMBIX_VM_AREAS_BITS 7

extern struct hlist_head AMBIX_VM_AREAS[1 << AMBIX_VM_AREAS_BITS];

extern struct mutex VM_AREAS_LOCK;

int ambix_bind_pid_constrained(const pid_t nr, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size);

int ambix_bind_pid(const pid_t nr);

int ambix_unbind_pid(const pid_t nr);

int ambix_unbind_range_pid(const pid_t nr, unsigned long start,
			   unsigned long end);

void refresh_bound_vm_areas(void);

struct vm_area_t * ambix_get_vm_area(unsigned long allocation_site);

#endif // VM_MANAGEMENT_H
