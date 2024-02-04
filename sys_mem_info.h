#ifndef SYS_MEM_INFO_H
#define SYS_MEM_INFO_H

#define K(x) ((x) << (PAGE_SHIFT - 10))

enum pool_t { DRAM_POOL, NVRAM_POOL };

extern const int DRAM_NODES[];
extern const int NVRAM_NODES[];

extern const int n_dram_nodes;
extern const int n_nvram_nodes;

extern struct proc_dir_entry *proc_dir;


extern struct mutex USAGE_mtx;

int is_page_in_pool(pte_t pte_t, enum pool_t pool);

void walk_ranges_usage(void);

const int *get_pool_nodes(const enum pool_t pool);

size_t get_pool_size(const enum pool_t pool);

const char *get_pool_name(const enum pool_t pool);

u32 get_real_memory_usage_per(enum pool_t pool);

u32 get_memory_usage_percent(enum pool_t pool);

u64 get_memory_total_ratio(enum pool_t pool);

u64 get_memory_total(enum pool_t pool);

#endif // SYS_MEM_INFO_H
