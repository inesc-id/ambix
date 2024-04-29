#ifndef AMBIX_H
#define AMBIX_H

struct mem_info {
	unsigned long slow_tier_usage_bytes;
	unsigned long fast_tier_usage_bytes;
	unsigned long allocation_site;
};

int bind(int pid, int migrations_enabled);
int bind_proc_(void); // fortran
int unbind(int pid);
int unbind_(void); // fortran

int enable(void);
int disable(void);

// Monitoring only

int bind_range_monitoring(int pid, unsigned long start, unsigned long end,
			      unsigned long allocation_site,
			      unsigned long size);

int unbind_range_monitoring(int pid, unsigned long start,
				unsigned long end);

int get_object_mem_info(unsigned long start_addr, struct mem_info *info);
int get_program_mem_info(struct mem_info *info);


#endif
