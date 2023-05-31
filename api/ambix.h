#ifndef AMBIX_H
#define AMBIX_H

int bind_range(unsigned long start, unsigned long end);
int bind_range_pid(int pid, unsigned long start, unsigned long end);
int bind(void);
int unbind(void);
int bind_pid(int pid);
int unbind_pid(int pid);
int enable(void);
int disable(void);
#endif
