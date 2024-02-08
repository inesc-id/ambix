#include "api/ambix.h"
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
#define ACCESS_PERCENTAGE 50

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

	// Calculate how many pages to access
	size_t pages = size / 4096;
	size_t pages_to_access = (pages * access_percentage) / 100;

	// Access the pages
	for (size_t i = 0; i < pages_to_access; i++) {
		ptr[i * 4096] = 42;
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
				       ACCESS_PERCENTAGE);
		simulate_memory_access(optane_ranges[i], RANGE_SIZE,
				       ACCESS_PERCENTAGE);
	}

	// Wait for 3 seconds to allow the monitoring thread to update the memory info
	sleep(3);

	// Print how many memory each range should theoretically have used
	printf("Theoretical Single Range Usage: %d B\n",
	       RANGE_SIZE * ACCESS_PERCENTAGE / 100);

	// Get and print memory info for each range
	for (int i = 0; i < NUM_RANGES; i++) {
		if (get_object_mem_info((unsigned long)dram_ranges[i], &info) ==
		    0) {
			printf("DRAM Range %d: ", i);
			print_mem_info(&info);
		} else {
			printf("error openning file\n");
		}
		if (get_object_mem_info((unsigned long)optane_ranges[i],
					&info) == 0) {
			printf("Optane Range %d: ", i);
			print_mem_info(&info);
		} else {
			printf("error openning file\n");
		}
	}

	// Print numastat information with current process
	system("numastat -p %d", getpid());

	// Print how much memory each tier should theoretically have used
	printf("Theoretical Total Program Memory Usage Per Tier: %d B\n",
	       RANGE_SIZE * NUM_RANGES * ACCESS_PERCENTAGE / 100);

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

	// Wait for 3 seconds to allow the monitoring thread to update the memory info
	sleep(3);

	// Print how many memory each range should theoretically have used
	printf("Theoretical Remaining Single Range Usage: %d B\n",
	       RANGE_SIZE * ACCESS_PERCENTAGE / 100);

	// Verify remaining ranges and total program memory info again
	for (int i = 0; i < NUM_RANGES; i++) {
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

	// Print numastat information with current process
	system("numastat -p %d", getpid());

	// Print how much memory each tier should theoretically have used
	printf("Theoretical Total Program Memory Usage Per Tier: %d B\n",
	       RANGE_SIZE * (NUM_RANGES - 1) * ACCESS_PERCENTAGE / 100);

	// Check total program memory info again
	if (get_program_mem_info(&info) == 0) {
		printf("Remaining Total Program Memory Info: ");
		print_mem_info(&info);
	}

	// Try to bind a range with invalid parameters
	if (bind_range_monitoring(0, 0, 0, 0) != 0) {
		printf("Error handling test passed: Invalid bind operation failed as expected.\n");
	}

	// Try to unbind a range that was not bound
	if (unbind_range_monitoring((unsigned long)dram_ranges[0],
				    (unsigned long)dram_ranges[0] +
					    RANGE_SIZE) != 0) {
		printf("Error handling test passed: Invalid unbind operation failed as expected.\n");
	}

	// Try to bind a range that was already bound
	if (bind_range_monitoring((unsigned long)dram_ranges[1],
				  (unsigned long)dram_ranges[1] + RANGE_SIZE,
				  DRAM_NODE, RANGE_SIZE) != 0) {
		printf("Error handling test passed: Invalid bind operation failed as expected.\n");
	}

	// Cleanup
	for (int i = 0; i < NUM_RANGES; i++) {
		numa_free(dram_ranges[i], RANGE_SIZE);
		numa_free(optane_ranges[i], RANGE_SIZE);
	}

	return 0;
}
