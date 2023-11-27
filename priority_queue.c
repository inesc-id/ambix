/**
 * @file    priority_queue.c
 * @author  INESC-ID
 * @date    23 oct 2023
 * @version 1.0.0
 * @brief   Data structure to help classify page according to access
 * frequency.       
 */

#include "priority_queue.h" // Include the header file here

inline void enqueue_address(priority_queue *pds, unsigned long address,
			    size_t pid, enum access_freq_t access_freq)
{
	if (pds->index[access_freq] < MAX_ADDRESSES) {
		pds->addresses[access_freq][pds->index[access_freq]].addr =
			address;
		pds->addresses[access_freq][pds->index[access_freq]++].pid_idx =
			pid;
	}
}

u32 address_count(priority_queue *pds)
{
	u32 priority, count = 0;
	for (priority = COLD_PAGE; priority < NUM_FREQ_TYPES; priority++)
		count += pds->index[priority];
	return count;
}

void clear_queue(priority_queue *pds)
{
	int priority;
	for (priority = COLD_PAGE; priority < NUM_FREQ_TYPES; priority++)
		pds->index[priority] = 0;
}
