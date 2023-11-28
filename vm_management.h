#ifndef VM_MANAGEMENT_H
#define VM_MANAGEMENT_H

// sets the number of virtual memory ranges that can be bound to Ambix at any given time
#define MAX_VM_AREAS 20

#define IS_64BIT (sizeof(void *) == 8)
#define MAX_ADDRESS                                                            \
	(IS_64BIT ?                                                            \
		 0xFFFF880000000000UL :                                        \
		 0xC0000000UL) // Max user-space addresses for the x86 architecture

struct vm_area_t {
	struct pid *__pid;
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long allocation_site;
	unsigned long size;
};

extern struct vm_area_t AMBIX_VM_AREAS[MAX_VM_AREAS];
extern size_t VM_AREAS_COUNT;
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

#endif // VM_MANAGEMENT_H
