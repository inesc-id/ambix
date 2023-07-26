# Ambix - Dynamic Page Placement on Real Persistent Memory Systems
**[Paper](https://arxiv.org/abs/2112.12685) on the first version of Ambix.**

## Dependencies
- GCC (>= 8.3.0)
- GNU Make (>= 4.2.1)
- [Linux](https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.tar.xz) (>= 5.10.0 & < 5.11.0)
- Numactl (>= 2.0.12)

## Build and Run
1. Check the machine's topology using `numactl -H`
    - Note: The NVRAM numa node ID should always be higher than the rest of the IDs.
2. Change the following files according to the result of step above

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
#define USAGE_FACTOR 100
#define DRAM_USAGE_TARGET 95
#define DRAM_USAGE_LIMIT 96
#define NVRAM_USAGE_TARGET 95
#define NVRAM_USAGE_LIMIT 98

#define NVRAM_BW_THRESH 10
```
3. Build the kernel module using GNU Make.
```sh
make
```
4. Insert the module.
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
