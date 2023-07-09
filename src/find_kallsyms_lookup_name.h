#pragma once

unsigned long extern (*the_kallsyms_lookup_name)(const char *name);

int find_kallsyms_lookup_name(void);
