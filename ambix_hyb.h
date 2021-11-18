#pragma once

int ambix_init(void);
void ambix_cleanup(void);

void ambix_check_memory(void);

int ambix_bind_pid(pid_t pid);
int ambix_unbind_pid(pid_t pid);

//int ambix_mem_walk(int n, int mode);
//int ambix_clear_walk(int mode);
//int ambix_switch_walk(int n);

//int ambix_find(int n_pages, int mode);
