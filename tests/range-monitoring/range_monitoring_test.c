#include "ambix.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <numa.h>
#include <errno.h>

#define NUM_RANGES 3
#define RANGE_SIZE (1024 * 1024) // 1MB
#define DRAM_NODE 0
#define OPTANE_NODE 2

// Helper function to map memory and bind to NUMA node
void *map_numa_memory(size_t size, int numa_node)
{
	void *addr = numa_alloc_onnode(size, numa_node);
	if (addr == NULL) {
		perror("numa_alloc_onnode failed");
		exit(EXIT_FAILURE);
	}
	return addr;
}

// Function to simulate memory access
void simulate_memory_access(void *addr, size_t size, int access_percentage)
{
	volatile char *ptr = addr;
	for (size_t i = 0; i < size; i += (size / 100)) {
		if (i % 100 < (size_t)access_percentage) {
			ptr[i] = (ptr[i] + 1) %
				 256; // Simple write to simulate access
		}
	}
}

// Print memory info
void print_mem_info(struct mem_info *info)
{
	printf("Slow Tier Usage Bytes: %lu, Fast Tier Usage Bytes: %lu, Allocation Site: %lu\n",
	       info->slow_tier_usage_bytes, info->fast_tier_usage_bytes,
	       info->allocation_site);
}

int main()
{
	if (numa_available() < 0) {
		fprintf(stderr, "NUMA is not available\n");
		return -1;
	}

	// Arrays to hold memory range addresses for DRAM and Optane
	void *dram_ranges[NUM_RANGES];
	void *optane_ranges[NUM_RANGES];
	struct mem_info info;

	// Map and bind memory ranges to DRAM and Optane
	for (int i = 0; i < NUM_RANGES; i++) {
		dram_ranges[i] = map_numa_memory(RANGE_SIZE, DRAM_NODE);
		optane_ranges[i] = map_numa_memory(RANGE_SIZE, OPTANE_NODE);
		bind_range_monitoring((unsigned long)dram_ranges[i],
				      (unsigned long)dram_ranges[i] +
					      RANGE_SIZE,
				      DRAM_NODE, RANGE_SIZE);
		bind_range_monitoring((unsigned long)optane_ranges[i],
				      (unsigned long)optane_ranges[i] +
					      RANGE_SIZE,
				      OPTANE_NODE, RANGE_SIZE);
	}

	// Simulate memory access
	for (int i = 0; i < NUM_RANGES; i++) {
		simulate_memory_access(dram_ranges[i], RANGE_SIZE,
				       50); // 50% access
		simulate_memory_access(optane_ranges[i], RANGE_SIZE,
				       50); // 50% access
	}

	// Get and print memory info for each range
	for (int i = 0; i < NUM_RANGES; i++) {
		if (get_object_mem_info((unsigned long)dram_ranges[i], &info) ==
		    0) {
			printf("DRAM Range %d: ", i);
			print_mem_info(&info);
		}
		if (get_object_mem_info((unsigned long)optane_ranges[i],
					&info) == 0) {
			printf("Optane Range %d: ", i);
			print_mem_info(&info);
		}
	}

	// Get and print total program memory info
	if (get_program_mem_info(&info) == 0) {
		printf("Total Program Memory Info: ");
		print_mem_info(&info);
	}

	// Unbind one range from each tier and verify
	unbind_range_monitoring((unsigned long)dram_ranges[0],
				(unsigned long)dram_ranges[0] + RANGE_SIZE);
	unbind_range_monitoring((unsigned long)optane_ranges[0],
				(unsigned long)optane_ranges[0] + RANGE_SIZE);

	// Verify remaining ranges and total program memory info again
	for (int i = 1; i < NUM_RANGES;
	     i++) { // Start from 1 since 0 was unbound
		if (get_object_mem_info((unsigned long)dram_ranges[i], &info) ==
		    0) {
			printf("Remaining DRAM Range %d: ", i);
			print_mem_info(&info);
		}
		if (get_object_mem_info((unsigned long)optane_ranges[i],
					&info) == 0) {
			printf("Remaining Optane Range %d: ", i);
			print_mem_info(&info);
		}
	}

	// Check total program memory info again
	if (get_program_mem_info(&info) == 0) {
		printf("Remaining Total Program Memory Info: ");
		print_mem_info(&info);
	}

	// Error handling test
	if (bind_range_monitoring(0, 0, 0, 0) != 0) {
		printf("Error handling test passed: Invalid bind operation failed as expected.\n");
	}

	// Cleanup
	for (int i = 0; i < NUM_RANGES; i++) {
		numa_free(dram_ranges[i], RANGE_SIZE);
		numa_free(optane_ranges[i], RANGE_SIZE);
	}

	return 0;
}
