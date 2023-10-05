#ifndef __PERF_COUNTERS_H__
#define __PERF_COUNTERS_H__

size_t extern EVENTs_size;

int perf_counters_init(void);
void perf_counters_cleanup(void);

void perf_counters_enable(void);
void perf_counters_disable(void);

bool perf_counters_read_change(size_t idx, u64 *value, u64 *jiffies);
struct counter_t *const perf_counters_info(size_t idx);

u64 jiffies_to_sec(const u64 jf);

unsigned long long perf_counters_pmm_writes(void);
unsigned long long perf_counters_pmm_reads(void);
unsigned long long perf_counters_ddr_writes(void);
unsigned long long perf_counters_ddr_reads(void);

struct counter_t {
  u64 event;
  u32 mult;
  u32 fact;
  char *name;
  char *unit;
};
#endif
