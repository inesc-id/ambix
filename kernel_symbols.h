#ifndef KERNEL_SYMBOLS_H
#define KERNEL_SYMBOLS_H

#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/init.h> // Macros used to mark up functions e.g., __init __exit
#include <linux/kernel.h> // Contains types, macros, functions for the kernel
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/migrate.h>
#include <linux/module.h> // Core header for loading LKMs into the kernel
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/shmem_fs.h>
#include <linux/signal.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <linux/huge_mm.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mmzone.h> // Contains conversion between pfn and node id (NUMA node)
#include <linux/mutex.h>
#include <linux/pagewalk.h>
#include <linux/string.h>

#define M(RET, NAME, SIGNATURE) \
    typedef RET(*NAME##_t) SIGNATURE; \
    extern NAME##_t g_##NAME;

#include "IMPORT.M"

#undef M

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 5)
extern atomic_t *g_lru_disable_count;
#endif


int import_symbols(void);

#endif // KERNEL_SYMBOLS_H
