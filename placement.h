#ifndef __PLACEMENT_H__
#define __PLACEMENT_H__

int ambix_init(void);
void ambix_cleanup(void);
int ambix_check_memory(void);

extern unsigned long long g_promotion_count;
extern unsigned long long g_demotion_count;

#endif
