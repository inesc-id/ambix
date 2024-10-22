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
2. Check the machine's node topology using `numactl -H`.
   
   You should choose a pair of nodes to be used by the application(s) that will be managed by Ambix:

   - One node with one or more cores ("cpus"). This node will hold DRAM (the top memory tier) and the associated cores ("cpus") will run the threads of the application.
   - One "cpu-less" node. This node will hold the second memory tier, typically non-volatile RAM (NVRAM).
   
   The first node must have a lower id than the second node; and both nodes should reside in the same socket.
   
4. Change the following files according to the previous choice.

   In the following examples, we assume that the chosen nodes are 0 (DRAM node with cores/"cpus") and 2 (NVRAM "cpu-less" node).

**config.h**
```C
// CHANGE THIS ACCORDING TO POINT 2 of the README
#define _CPUs {0}
#define _DRAM_NODES {0}
#define _NVRAM_NODES {2}

// tune these parameters according to preference
// Ratio of real DRAM available to Ambix.
// e.g. If the machine has 8GiB of RAM but the user only wants Ambix to see 4GiB, this parameter should be set to 50
#define DRAM_MEM_USAGE_RATIO 100
// Ratio of real NVRAM available to Ambix
// Analogous to DRAM_USAGE_RATIO
#define NVRAM_MEM_USAGE_RATIO 100

//The following parameters are used to control when Ambix should initiate page migration between memory tiers
//The "_PERCENTAGE" parameters are relative to the amount of memory available to Ambix at each node

// Target DRAM usage: if DRAM usage is lower than this and NVRAM has candidate pages, Ambix will
// try to migrate them to DRAM until the limit DRAM usage is reached
#define DRAM_MEM_USAGE_TARGET_PERCENT 95

// DRAM usage limit (must be higher than target DRAM usage): when DRAM usage exceeds this limit,
// Ambix will try to evict cold pages from DRAM to NVRAM until the target DRAM usage is reached
// (note: these downstream migrations are only performed as long as NVRAM usage is below the target NVRAM usage).
#define DRAM_MEM_USAGE_LIMIT_PERCENT 96

// Target NVRAM usage: parameter that restricts the eviction of DRAM pages (see description of DRAM usage limit)
// and the promotion of NVRAM pages when NVRAM usage is above its limit (see next)
#define NVRAM_MEM_USAGE_TARGET_PERCENT 95

// NVRAM usage limit (must be higher than target NVRAM usage): if NVRAM usage is above this limit and DRAM usage is below its target, Ambix will promote enough
// candidate pages until the target NVRAM usage is reached
#define NVRAM_MEM_USAGE_LIMIT_PERCENT 98

// NVRAM bandwidth usage threshold: when Ambix observes that NVRAM bandwidth usage is above this threshold,
// it will try to select candidate hot pages from NVRAM (that are likely to contribute to the high NVRAM bandwidth usage)
// and promote them
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


// Bind to Ambix only for memory monitoring
int bind_range_monitoring(unsigned long start, unsigned long end, unsigned long allocation_site, unsigned long size)
int bind_range_monitoring_pid(int pid, unsigned long start, unsigned long end, unsigned long allocation_site, unsigned long size)

int unbind_range_monitoring(unsigned long start, unsigned long end)
int unbind_range_monitoring_pid(int pid, unsigned long start, unsigned long end)

// Data Collection Functions
int get_program_mem_info(struct mem_info *info)  //Returns 0 if successful, -1 otherwise.

int get_object_mem_info(unsigned long start_addr, mem_info *info)  //Returns 0 if successful, -1 otherwise.

// Note: The `start_addr` serves as a unique identifier for each program's objects

struct mem_info {
	unsigned long slow_tier_usage_bytes;
	unsigned long fast_tier_usage_bytes;
	unsigned long allocation_site;         // set to -1 when used with get_program_mem_info
};


```
