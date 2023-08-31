# Ambix - Dynamic Page Placement on Real Persistent Memory Systems
**[Paper](https://arxiv.org/abs/2112.12685) on the first version of Ambix.**

## Dependencies
- GCC (>= 8.3.0)
- GNU Make (>= 4.2.1)
- [Linux](https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.tar.xz) (>= 5.10.0 & < 5.11.0)
- Numactl (>= 2.0.12)

## Build and Run
1. Disable Linux's default numa node balancing, swappiness and Transparent Huge Pages
```sh
sudo su
echo 0 > /proc/sys/kernel/numa_balancing
sysctl vm.swappiness=0
echo never > /sys/kernel/mm/transparent_hugepage/enabled
exit
```
2. Check the machine's topology using `numactl -H`
    - Note: The NVRAM numa node ID should always be higher than the rest of the IDs.
3. Change the following files according to the result of step above

**perf_counters.c**
```C
// perf_counters.c: lines 17 and 18
// CHANGE DEPENDING ON HARDWARE CONFIGURATION
static u32 CPUs[] = {0}; // We only read events from the CPU in numa node 0
```
**placement.c**
```C
// placement.c: lines 88 and 89
// CHANGE THIS ACCORDING TO HARDWARE CONFIGURATION
static const int DRAM_NODES[] = {0};
static const int NVRAM_NODES[] = {2};
```
**placement.c (optional)**
```C
// placement.c: lines 53-59
// tune these parameters according to preference

// Ratio of real DRAM available to Ambix
// e.g. If the machine has 8GiB of RAM but the user only wants Ambix to see 4, this is set to 50
#define DRAM_MEM_USAGE_RATIO 100
// Ratio of real NVRAM available to Ambix
// Analogous to DRAM_USAGE_RATIO
#define NVRAM_MEM_USAGE_RATIO 100

// All the 4 ratios below are relative to the amount of memory available to Ambix, depending on the two above parameters
// optimal DRAM usage percentage (if usage is lower than this and NVRAM has candidate pages to be migrated, they are)
#define DRAM_MEM_USAGE_TARGET_PERCENT 95
// Ambix keeps DRAM usage always under this ratio
#define DRAM_MEM_USAGE_LIMIT_PERCENT 96
// If memory usage in NVRAM is below target and DRAM usage is above limit, pages will be migrated
#define NVRAM_MEM_USAGE_TARGET_PERCENT 95
// Used to switch pages between NVRAM and DRAM if usage in NVRAM is above limit and in DRAM below target
#define NVRAM_MEM_USAGE_LIMIT_PERCENT 98

// Used to check if NVRAM bandwidth is saturated
#define NVRAM_BANDWIDTH_THRESHOLD 10
```
4. Build the kernel module using GNU Make.
```sh
make
```
5. Insert the module.
```sh
make insert
# or
sudo insmod ./ambix.ko
# when finished, remove using
make remove
# or
sudo rmmod ambix
```

## Usage
Every interaction between user space and Ambix is done using the procfs. To facilitate
binding applications to be managed by ambix we provide an API.
```C
int bind_range(unsigned long start, unsigned long end, unsigned long allocation_site, unsigned long size);
int bind_range_pid(int pid, unsigned long start, unsigned long end, unsigned long allocation_site, unsigned long size);
int bind(void);
int unbind(void);
int bind_pid(int pid);
int unbind_pid(int pid);
int unbind_range(unsigned long start, unsigned long end);
int unbind_range_pid(int pid, unsigned long start, unsigned long end);
int enable(void);
int disable(void);
```

## Disclaimer
There is a known bug when a process finishes and doesn't unbind from Ambix. If it is doing a `walk_page_range` or migrating pages it might cause a null pointer dereference.
