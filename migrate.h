#ifndef MIGRATE_H
#define MIGRATE_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/list.h>
#include "memory_info.h"

typedef struct addr_info {
  unsigned long addr;
  size_t pid_idx;
} addr_info_t;


int do_migration(const addr_info_t *const found_addrs, const size_t n_found, const enum pool_t dst);

#endif // MIGRATE_H
