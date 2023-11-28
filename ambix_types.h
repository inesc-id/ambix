#ifndef AMBIX_TYPES_H
#define AMBIX_TYPES_H

#include <stddef.h>
#include <linux/kernel.h>

#define MAX_ADDRESSES 131071U

#define COLDER_PAGES_FIRST 0
#define WARMER_PAGES_FIRST 1

#define FREQ_ORDERED_TRAVERSE(heat_map, priority, address, vm_area_idx)                 \
	int __freq__, __i__;                                                   \
	for (__freq__ = priority == COLDER_PAGES_FIRST ? 0 :                   \
							 NUM_FREQ_TYPES - 1;   \
	     __freq__ >= 0 && __freq__ < NUM_FREQ_TYPES;                       \
	     priority == COLDER_PAGES_FIRST ? __freq__++ : __freq__--)         \
		for (__i__ = 0;                                                \
		     __i__ < heat_map->index[__freq__] && ({                        \
			     vm_area_idx =                                         \
				     heat_map->addresses[__freq__][__i__].vm_area_idx;  \
			     address = heat_map->addresses[__freq__][__i__].addr;   \
			     1;                                                \
		     });                                                       \
		     __i__++)

enum access_freq_t {
	COLD_PAGE,
	WARM_DIRTY_PAGE,
	WARM_ACCESSED_PAGE,
	HOT_PAGE,
	NUM_FREQ_TYPES
};

// Define your struct and function declarations here
typedef struct addr_info {
	unsigned long addr;
	size_t vm_area_idx;
} addr_info_t;

typedef struct vm_heat_map{
	addr_info_t addresses[NUM_FREQ_TYPES][MAX_ADDRESSES];
	int index[NUM_FREQ_TYPES];
} vm_heat_map;

void heat_map_add_page(struct vm_heat_map *heat_map, unsigned long address, size_t pid,
		     enum access_freq_t access_freq);
u32 heat_map_size(struct vm_heat_map *heat_map);
void heat_map_clear(struct vm_heat_map *heat_map);
u32 heat_map_compare(struct vm_heat_map *heat_map_1, struct vm_heat_map *heat_map_2);

#endif
