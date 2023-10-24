#ifndef MIGRATE_H
#define MIGRATE_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/list.h>
#include "memory_info.h"
#include "priority_queue.h"

int do_migration(priority_queue *pds, const size_t n_to_migrate,
		 const enum pool_t dst, int priority);

#endif // MIGRATE_H
