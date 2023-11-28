#ifndef MIGRATE_H
#define MIGRATE_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/list.h>
#include "sys_mem_info.h"
#include "ambix_types.h"

int do_migration(struct vm_heat_map *pds, const size_t n_to_migrate,
		 const enum pool_t dst, int priority);

#endif // MIGRATE_H
