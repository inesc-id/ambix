/**
 * @file    ambix_types.c
 * @author  INESC-ID
 * @date    23 oct 2023
 * @version 1.0.0
 * @brief   Data structure to help classify page according to access
 * frequency.       
 */

#include "ambix_types.h" // Include the header file here

inline void heat_map_add_page(struct vm_heat_map *heat_map,
			      unsigned long address, struct pid *pid_p,
			      enum access_freq_t access_freq)
{
	if (heat_map->index[access_freq] < MAX_ADDRESSES) {
		heat_map->addresses[access_freq][heat_map->index[access_freq]]
			.addr = address;
		heat_map->addresses[access_freq][heat_map->index[access_freq]++]
			.vm_area_pid = pid_p;
	}
}

u32 heat_map_size(struct vm_heat_map *heat_map)
{
	u32 priority, count = 0;
	for (priority = COLD_PAGE; priority < NUM_FREQ_TYPES; priority++)
		count += heat_map->index[priority];
	return count;
}

// Clears the heat_map size indices, effectively resetting the heat_map
void heat_map_clear(struct vm_heat_map *heat_map)
{
	int priority;
	for (priority = COLD_PAGE; priority < NUM_FREQ_TYPES; priority++)
		heat_map->index[priority] = 0;
}

// Returns number of pages in heat_map_1 which are hotter than pages in heat_map_2
u32 heat_map_compare(struct vm_heat_map *heat_map_1,
		     struct vm_heat_map *heat_map_2)
{
	enum access_freq_t access_freq_1 = HOT_PAGE;
	enum access_freq_t access_freq_2 = HOT_PAGE - 1;

	int page_count_map_1 = heat_map_1->index[access_freq_1];
	int page_count_map_2 = heat_map_2->index[access_freq_2];
	int page_count_diff;

	int n_hotter_pages = 0;

	while (access_freq_1 > COLD_PAGE) {
		page_count_diff = min(page_count_map_1, page_count_map_2);
		n_hotter_pages += page_count_diff;

		page_count_map_1 -= page_count_diff;
		page_count_map_2 -= page_count_diff;

		if (page_count_map_1 == 0) {
			page_count_map_1 = heat_map_1->index[--access_freq_1];
		}

		if (page_count_map_2 == 0) {
			if (access_freq_2 == COLD_PAGE)
				break;

			page_count_map_2 = heat_map_2->index[--access_freq_2];
		}
	}

	return n_hotter_pages;
}
