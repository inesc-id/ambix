#ifndef AMBIX_TYPES_H
#define AMBIX_TYPES_H

#include <stddef.h>
#include <linux/kernel.h>

#define MAX_ADDRESSES 131071U

#define COLDER_PAGES_FIRST 0
#define WARMER_PAGES_FIRST 1

/*
 * FREQ_ORDERED_TRAVERSE is a macro that traverses a heat_map in order of page "temperature".
 * It sets up two loop variables, __freq__ and __i__, to iterate over the heat_map.
 * The outer loop, controlled by __freq__, represents the frequency type (or "temperature" of the pages).
 * The starting value of __freq__ depends on the priority parameter:
 * - If priority is COLDER_PAGES_FIRST, it starts from 0 (colder pages) and increments towards NUM_FREQ_TYPES - 1 (hotter pages).
 * - If priority is WARMER_PAGES_FIRST, it starts from NUM_FREQ_TYPES - 1 (hotter pages) and decrements towards 0 (colder pages).
 * The inner loop, controlled by __i__, represents the index of the addresses within each frequency type.
 * For each frequency type, it traverses all addresses stored in the heat_map.
 * Inside the inner loop, it assigns the current address and its corresponding vm_area_pid to the address and vm_area_idx variables respectively.
 * It's the start of a for loop, with the internal loop block being implemented elsewhere.
 */
#define FREQ_ORDERED_TRAVERSE(heat_map, priority, address, vm_area_idx)         \
	int __freq__, __i__;                                                    \
	for (__freq__ = priority == COLDER_PAGES_FIRST ? 0 :                    \
							 NUM_FREQ_TYPES - 1;    \
	     __freq__ >= 0 && __freq__ < NUM_FREQ_TYPES;                        \
	     priority == COLDER_PAGES_FIRST ? __freq__++ : __freq__--)          \
		for (__i__ = 0;                                                 \
		     __i__ < heat_map->index[__freq__] && ({                    \
			     vm_area_idx =                                      \
				     heat_map->addresses[__freq__][__i__]       \
					     .vm_area_pid;                      \
			     address =                                          \
				     heat_map->addresses[__freq__][__i__].addr; \
			     1;                                                 \
		     });                                                        \
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
	struct pid *vm_area_pid;
} addr_info_t;

typedef struct vm_heat_map {
	addr_info_t addresses[NUM_FREQ_TYPES][MAX_ADDRESSES];
	int index[NUM_FREQ_TYPES];
} vm_heat_map;

void heat_map_add_page(struct vm_heat_map *heat_map, unsigned long address,
		       struct pid *pid_p, enum access_freq_t access_freq);
u32 heat_map_size(struct vm_heat_map *heat_map);
void heat_map_clear(struct vm_heat_map *heat_map);
u32 heat_map_compare(struct vm_heat_map *heat_map_1,
		     struct vm_heat_map *heat_map_2);

#endif
