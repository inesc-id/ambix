#ifndef AMBIX_H
#define AMBIX_H

struct mem_info {
	unsigned long slow_tier_usage_bytes;
	unsigned long fast_tier_usage_bytes;
	unsigned long allocation_site;
};

int bind_range(unsigned long start, unsigned long end,
	       unsigned long allocation_site, unsigned long size);
int bind_range_pid(int pid, unsigned long start, unsigned long end,
		   unsigned long allocation_site, unsigned long size);
int bind(void);
int bind_proc_(void); // fortran
int unbind(void);
int unbind_(void); // fortran
int bind_pid(int pid);
int unbind_pid(int pid);
int unbind_range(unsigned long start, unsigned long end);
int unbind_range_pid(int pid, unsigned long start, unsigned long end);
int enable(void);
int disable(void);
int get_mem_info(unsigned long start_addr, mem_info *info);
#endif
