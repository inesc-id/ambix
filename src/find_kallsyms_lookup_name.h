#ifndef __FIND_KALLSYMS_LOOKUP_NAME_H__
#define __FIND_KALLSYMS_LOOKUP_NAME_H__

unsigned long extern (*the_kallsyms_lookup_name)(const char *name);

int find_kallsyms_lookup_name(void);
#endif
