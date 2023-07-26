#ifndef AMBIX_H
#define AMBIX_H

int bind_range(unsigned long start, unsigned long end, unsigned long allocation_site, unsigned long size);
int bind_range_pid(int pid, unsigned long start, unsigned long end, unsigned long allocation_site, unsigned long size);
int bind(void);
int unbind(void);
int bind_pid(int pid);
int unbind_pid(int pid);
int unbind_range(unsigned long start, unsigned long end);
int unbind_range_pid(int pid, unsigned long start, unsigned long end);
int enable(void);
int disable(void);
#endif
