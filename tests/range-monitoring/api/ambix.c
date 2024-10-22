#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ambix.h"

int write_procfs(char *command)
{
	FILE *f = fopen("/proc/ambix/objects", "w");

	if (!f)
		goto fail_return;

	fprintf(f, "%s", command);

	fclose(f);

	return 0;

fail_return:
	errno = -EINVAL;
	return 1;
}

int enable(void)
{
	return write_procfs("enable");
}

int disable(void)
{
	return write_procfs("disable");
}

int bind_proc_(void)
{
	return bind(0, 1);
}

int bind(int pid, int migrations_enabled)
{
	char buffer[1024];
	snprintf(buffer, 1023, "bind %d %d", pid, migrations_enabled);
	return write_procfs(buffer);
}

int unbind(int pid)
{
	char buffer[1024];
	snprintf(buffer, 1023, "unbind %d", pid);
	return write_procfs(buffer);
}

int unbind_range(int pid, unsigned long start, unsigned long end)
{
	char buffer[1024];
	snprintf(buffer, 1023, "unbind_range %d %lx %lx", pid, start, end);
	return write_procfs(buffer);
}

/************************ Memory Monitoring Only ******************************/

int bind_range_monitoring(int pid, unsigned long start, unsigned long end,
			  unsigned long allocation_site, unsigned long size)
{
	char buffer[1024];
	snprintf(buffer, 1023, "bind_range_monitoring %d %lx %lx %lx %lx", pid,
		 start, end, allocation_site, size);
	return write_procfs(buffer);
}

int unbind_range_monitoring(int pid, unsigned long start, unsigned long end)
{
	char buffer[1024];
	snprintf(buffer, 1023, "unbind_range_monitoring %d %lx %lx", pid, start,
		 end);
	return write_procfs(buffer);
}

int get_object_mem_info(unsigned long start_addr, struct mem_info *info)
{
	char path[256];
	FILE *file;
	int result;

	// Create the path to the proc file
	snprintf(path, sizeof(path), "/proc/ambix/%d.%lu", getpid(),
		 start_addr);

	// Open the proc file
	file = fopen(path, "r");
	if (file == NULL) {
		return -1;
	}

	// Read the proc file
	result = fscanf(file, "%*[^\n]\n%lu, %lu, %lu",
			&info->fast_tier_usage_bytes,
			&info->slow_tier_usage_bytes, &info->allocation_site);

	// Close the proc file
	fclose(file);

	if (result != 3) {
		return -1;
	}

	return 0;
}

int get_program_mem_info(struct mem_info *info)
{
	char path[256];
	FILE *file;
	int result;

	// Create the path to the proc file
	snprintf(path, sizeof(path), "/proc/ambix/objects");

	// Open the proc file
	file = fopen(path, "r");
	if (file == NULL) {
		return -1;
	}

	// Read the proc file
	result = fscanf(file, "%*[^\n]\n%lu, %lu, %lu",
			&info->fast_tier_usage_bytes,
			&info->slow_tier_usage_bytes, &info->allocation_site);

	// Close the proc file
	fclose(file);

	if (result != 3) {
		return -1;
	}

	return 0;
}