#ifndef __CONFIG_H__
#define __CONFIG_H__

// CHANGE THIS ACCORDING TO HARDWARE CONFIGURATION
#define _CPUs                                                                  \
	{                                                                      \
		0                                                              \
	}
#define _DRAM_NODES                                                            \
	{                                                                      \
		0                                                              \
	}
#define _NVRAM_NODES                                                           \
	{                                                                      \
		2                                                              \
	}
// tune these parameters according to preference

// Ratio of real DRAM available to Ambix.
// e.g. If the machine has 8GiB of RAM but the user only wants Ambix to see
// 4GiB, this parameter should be set to 50
#define DRAM_MEM_USAGE_RATIO 97
// Ratio of real NVRAM available to Ambix
// Analogous to DRAM_USAGE_RATIO
#define NVRAM_MEM_USAGE_RATIO 100

// The following parameters are used to control when Ambix should initiate page
// migration between memory tiers The "_PERCENTAGE" parameters are relative to
// the amount of memory available to Ambix at each node

// Target DRAM usage: if DRAM usage is lower than this and NVRAM has candidate
// pages, Ambix will try to migrate them to DRAM until the limit DRAM usage is
// reached
#define DRAM_MEM_USAGE_TARGET_PERCENT 95

// DRAM usage limit (must be higher than target DRAM usage): when DRAM usage
// exceeds this limit, Ambix will try to evict cold pages from DRAM to NVRAM
// until the target DRAM usage is reached (note: these downstream migrations are
// only performed as long as NVRAM usage is below the target NVRAM usage).
#define DRAM_MEM_USAGE_LIMIT_PERCENT 96

// Target NVRAM usage: parameter that restricts the eviction of DRAM pages (see
// description of DRAM usage limit) and the promotion of NVRAM pages when NVRAM
// usage is above its limit (see next)
#define NVRAM_MEM_USAGE_TARGET_PERCENT 95

// NVRAM usage limit (must be higher than target NVRAM usage): if NVRAM usage is
// above this limit and DRAM usage is below its target, Ambix will promote
// enough candidate pages until the target NVRAM usage is reached
#define NVRAM_MEM_USAGE_LIMIT_PERCENT 98

// NVRAM bandwidth usage threshold: when Ambix observes that NVRAM bandwidth
// usage is above this threshold, it will try to select candidate hot pages from
// NVRAM (that are likely to contribute to the high NVRAM bandwidth usage) and
// promote them
#define NVRAM_BANDWIDTH_THRESHOLD 10

// Log migrated pages into the kernel ring buffer
// Uncomment to print migrated pages
// #define DEBUG_MIGRATIONS

// TODO DOCUMENT
#define AMBIX_DRAM_HARD_LIMIT 97
#define AMBIX_NVRAM_HARD_LIMIT 100
#endif
