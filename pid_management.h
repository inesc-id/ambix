#ifndef PID_MANAGEMENT_H
#define PID_MANAGEMENT_H

#define MAX_PIDS                                                               \
	20 // sets the number of PIDs that can be bound to Ambix at any given time

#define IS_64BIT (sizeof(void *) == 8)
#define MAX_ADDRESS                                                            \
	(IS_64BIT ?                                                            \
		 0xFFFF880000000000UL :                                        \
		 0xC0000000UL) // Max user-space addresses for the x86 architecture

struct ambix_proc_t {
	struct pid *__pid;
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long allocation_site;
	unsigned long size;
};

extern struct ambix_proc_t PIDs[MAX_PIDS];
extern size_t PIDs_size;
extern struct mutex PIDs_mtx;

int ambix_bind_pid_constrained(const pid_t nr, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size);

int ambix_bind_pid(const pid_t nr);

int ambix_unbind_pid(const pid_t nr);

int ambix_unbind_range_pid(const pid_t nr, unsigned long start,
			   unsigned long end);

void refresh_pids(void);

#endif // PID_MANAGEMENT_H
