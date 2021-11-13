#pragma once

size_t extern EVENTs_size;

int perf_counters_init(void);
void perf_counters_cleanup(void);

void perf_counters_enable(void);
void perf_counters_disable(void);

bool perf_counters_read_change(const size_t idx, u64 * value, u64 * time);

