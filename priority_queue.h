#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include <stddef.h> 
#include <linux/kernel.h> // Contains types, macros, functions for the kernel

#define MAX_ADDRESSES 131071U

#define COLDER_PAGES_FIRST 0
#define WARMER_PAGES_FIRST 1

#define FREQ_ORDERED_TRAVERSE(pds, priority, address, pid_idx)                      \
	int __freq__, __i__;                                                   \
	for (__freq__ = priority == COLDER_PAGES_FIRST ? 0 : NUM_FREQ_TYPES - 1;  \
	     __freq__ >= 0 && __freq__ < NUM_FREQ_TYPES;                       \
	     priority == COLDER_PAGES_FIRST ? __freq__++ : __freq__--)            \
		for (__i__ = 0;                                                \
		     __i__ < pds->index[__freq__] && ({                        \
			     pid_idx =                                         \
				     pds->addresses[__freq__][__i__].pid_idx;  \
			     address = pds->addresses[__freq__][__i__].addr;   \
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
    size_t pid_idx;
} addr_info_t;

typedef struct {
    addr_info_t addresses[NUM_FREQ_TYPES][MAX_ADDRESSES];
    int index[NUM_FREQ_TYPES];
} priority_queue;

void enqueue_address(priority_queue *pds, unsigned long address, size_t pid, enum access_freq_t access_freq);
u32 address_count(priority_queue *pds);
void clear_queue(priority_queue *pds);

#endif
