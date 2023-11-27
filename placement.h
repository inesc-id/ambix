#ifndef __PLACEMENT_H__
#define __PLACEMENT_H__

int ambix_init(void);
void ambix_cleanup(void);

int ambix_check_memory(void);

int ambix_bind_pid(pid_t pid);
int ambix_bind_pid_constrained(pid_t pid, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size);
int ambix_unbind_pid(pid_t pid);
int ambix_unbind_range_pid(pid_t pid, unsigned long start, unsigned long end);
#endif
