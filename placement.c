/**
 * @file    placement.c
 * @author  Ilia Kuzmin <Ilia.Kuzmin@tecnico.ulisboa.pt>
 * @date    11 Jan 2022
 * @version 0.4
 * @brief  Page walker for finding page table entries' R/M bits. Intended for the 5.6.3 Linux kernel.
 * Adapted from the code provided by Reza Karimi <r68karimi@gmail.com>
 * Adapted from the code implemented by Miguel Marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#define DEBUG
#define pr_fmt(fmt) "hello.PLACEMENT: " fmt

#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/delay.h>
#include <linux/init.h>  // Macros used to mark up functions e.g., __init __exit
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/module.h>  // Core header for loading LKMs into the kernel
#include <linux/skbuff.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/shmem_fs.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/uaccess.h>
#include <linux/migrate.h>
#include <linux/swap.h>

#include <linux/huge_mm.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mmzone.h> // Contains conversion between pfn and node id (NUMA node)
#include <linux/pagewalk.h>
#include <linux/string.h>

#include "placement.h"
#include "find_kallsyms_lookup_name.h"
#include "perf_counters.h"

#define USAGE_FACTOR 100
#define DRAM_USAGE_TARGET 95
#define DRAM_USAGE_LIMIT 96
#define NVRAM_USAGE_TARGET 95
#define NVRAM_USAGE_LIMIT 98

#define NVRAM_BW_THRESH 10

#define MAX_N_FIND 131071U
#define MAX_N_SWITCH (MAX_N_FIND - 1) / 2 // Amount of switches that fit in exactly MAX_PACKETS netlink packets making space for begin and end struct
#define PMM_MIXED 1

#define MAX_PID_N 2147483647 // set to INT_MAX. true max pid number is shown in /proc/sys/kernel/pid_max
#define MAX_PIDS 500 // sets the number of PIDs that can be bound to Ambix at any given time

#define IS_64BIT (sizeof(void*) == 8)
#define MAX_ADDRESS (IS_64BIT ? 0xFFFF880000000000UL : 0xC0000000UL) // Max user-space addresses for the x86 architecture


#define DRAM_MODE 0
#define NVRAM_MODE 1
#define NVRAM_INTENSIVE_MODE 2
#define SWITCH_MODE 3
#define NVRAM_WRITE_MODE 5

// Node definition: DRAM nodes' (memory mode) ids must always be a lower value than NVRAM nodes' ids due to the memory policy set in client-placement.c
static const int DRAM_NODES[] = {0};
static const int NVRAM_NODES[] = {1}; // FIXME {2}

static const int n_dram_nodes = ARRAY_SIZE(DRAM_NODES);
static const int n_nvram_nodes = ARRAY_SIZE(NVRAM_NODES);

int g_nr_pids = 0;
struct task_struct ** g_task_items;

unsigned long g_last_addr_dram = 0;
unsigned long g_last_addr_nvram = 0;

int g_last_pid_dram = 0;
int g_last_pid_nvram = 0;

#define M(RET, NAME, SIGNATURE) \
    typedef RET (*NAME ## _t) SIGNATURE; \
    NAME ##_t g_ ##NAME
#include "IMPORT.M"
#undef M

// == typedef struct page * (*alloc_migration_target_t)(
// ==         struct page * page,
// ==         unsigned long private);
// == alloc_migration_target_t g_alloc_migration_target;

typedef struct addr_info
{
    unsigned long addr;
    size_t pid_idx;
} addr_info_t;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,5)
    /**
     * Can't import inline functions, have to duplicate:
     */
    atomic_t * g_lru_disable_count;

    static inline bool my_lru_cache_disable(void)
    { return atomic_read(g_lru_disable_count); }

    static inline void my_lru_cache_enable(void)
    { atomic_dec(g_lru_disable_count); }
#else
    static inline bool my_lru_cache_disable(void) {
        g_lru_add_drain_all();
        return true;
    }
    static inline void my_lru_cache_enable(void) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,6)
#define thp_nr_pages(head) hpage_nr_pages(head)
#endif


/*
-------------------------------------------------------------------------------

HELPER FUNCTIONS

-------------------------------------------------------------------------------
*/

//TODO: rewrite me
int contains(int value, int mode) {
    const int *array;
    int size, i;

    if(mode == NVRAM_MODE) {
        array = NVRAM_NODES;
        size = n_nvram_nodes;
    }
    else {
        array = DRAM_NODES;
        size = n_dram_nodes;
    }
    for(i=0; i<size; i++) {
        if(array[i] == value) {
            return 1;
        }
    }
    return 0;
}


static int find_target_process(pid_t pid)
{  // to find the task struct by process_name or pid
    int i;
    struct pid * pid_s;
    struct task_struct * t;

    if (g_nr_pids >= MAX_PIDS) {
        pr_info("Managed PIDs at capacity.\n");
        return 0;
    }
    for (i=0; i < g_nr_pids; i++) {
        if ((g_task_items[i] != NULL) && (g_task_items[i]->pid == pid)) {
            pr_info("Already managing given PID.\n");
            return 0;
        }
    }

    pid_s = find_get_pid(pid);
    if (pid_s == NULL) {
        return 0;
    }
    t = get_pid_task(pid_s, PIDTYPE_PID);
    put_pid(pid_s);
    if (t != NULL) {
        g_task_items[g_nr_pids++] = t;
        return 1;
    }

    return 0;
}

static int update_pid_list(int i)
{
    int j;
    if (g_last_pid_dram > i) {
        g_last_pid_dram--;
    }
    else if (g_last_pid_dram == i) {
        g_last_addr_dram = 0;

        if (g_last_pid_dram == (g_nr_pids-1)) {
            g_last_pid_dram = 0;
        }
    }

    if (g_last_pid_nvram > i) {
        g_last_pid_nvram--;
    }
    else if (g_last_pid_nvram == i) {
        g_last_addr_nvram = 0;

        if (g_last_pid_nvram == (g_nr_pids-1)) {
            g_last_pid_nvram = 0;
        }
    }

    // Shift left all subsequent entries
    for (j = i; j < (g_nr_pids - 1); j++) {
        g_task_items[j] = g_task_items[j+1];
    }

    g_nr_pids--;

    return 0;
}

static int refresh_pids(void)
{
    int i;
    for (i=0; i < g_nr_pids; i++) {
        if (g_task_items[i] != NULL) {
            struct pid * p = find_get_pid(g_task_items[i]->pid);
            put_pid(p);
            if (p != NULL)
                continue;
        }
        update_pid_list(i);
        i--;
    }

    for(i = 0; i < g_nr_pids; ++i) {
        pr_debug("Bound process: [%d]%d\n", i, g_task_items[i]->pid);
    }

    return 0;
}


// ==================================================================================
// CALLBACK FUNCTIONS
// ==================================================================================

struct pte_callback_context_t
{
    u32 n_found;
    u32 n_to_find;
    u32 n_backup;
    u32 n_switch_backup;

    size_t curr_pid_idx;

    addr_info_t found_addrs[MAX_N_FIND];
    addr_info_t backup_addrs[MAX_N_FIND]; // prevents a second page walk
    addr_info_t switch_backup_addrs[MAX_N_SWITCH]; // for switch walk
} static g_context = {0};

static int pte_callback_dram(
        pte_t *ptep,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *walk)
{
    struct pte_callback_context_t * ctx =
        (struct pte_callback_context_t *) walk->private;

    pte_t old_pte;
    // If found all, save last addr
    if (ctx->n_found == ctx->n_to_find) {
        pr_debug("Dram callback: found enough pages, storing last addr %lx\n", addr);
        g_last_addr_dram = addr;
        return 1;
    }

    // If page is not present, write protected, or not in DRAM node
    if ((ptep == NULL)
    || !pte_present(*ptep)
    || !pte_write(*ptep)
    || !contains(pfn_to_nid(pte_pfn(*ptep)), DRAM_MODE)) {
        return 0;
    }

    if (!pte_young(*ptep)) {
        // Send to NVRAM
        ctx->found_addrs[ctx->n_found].addr = addr;
        ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
        return 0;
    }

    if (!pte_dirty(*ptep)
    && (ctx->n_backup < (ctx->n_to_find - ctx->n_found))) {
        // Add to backup list
        ctx->backup_addrs[ctx->n_backup].addr = addr;
        ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
    }

    old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
    *ptep = pte_mkold(old_pte); // unset modified bit
    *ptep = pte_mkclean(old_pte); // unset dirty bit
    ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, *ptep);
    return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_force(
        pte_t *ptep,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *walk)
{
    struct pte_callback_context_t * ctx =
        (struct pte_callback_context_t *) walk->private;

    pte_t old_pte;

    // If found all save last addr
    if (ctx->n_found == ctx->n_to_find) {
        g_last_addr_nvram = addr;
        return 1;
    }

    // If page is not present, write protected, or not in NVRAM node
    if ((ptep == NULL)
    || !pte_present(*ptep)
    || !pte_write(*ptep)
    || !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
        return 0;
    }

    if(pte_young(*ptep) && pte_dirty(*ptep)) {
        // Send to DRAM (priority)
        ctx->found_addrs[ctx->n_found].addr = addr;
        ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
        return 0;
    }

    if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
        // Add to backup list
        ctx->backup_addrs[ctx->n_backup].addr = addr;
        ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
    }

    old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
    *ptep = pte_mkold(old_pte); // unset modified bit
    *ptep = pte_mkclean(old_pte); // unset dirty bit
    ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, *ptep);

    return 0;
}

// ----------------------------------------------------------------------------------

// used only for debug in ctl (NVRAM_WRITE_MODE)
static int pte_callback_nvram_write(
        pte_t *ptep,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *walk)
{
    struct pte_callback_context_t * ctx =
        (struct pte_callback_context_t *) walk->private;

    // If found all save last addr
    if (ctx->n_found == ctx->n_to_find) {
        g_last_addr_nvram = addr;
        return 1;
    }

    // If page is not present, write protected, or not in NVRAM node
    if ((ptep == NULL)
    || !pte_present(*ptep)
    || !pte_write(*ptep)
    || !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
        return 0;
    }

    if (pte_dirty(*ptep)) {
        if (pte_young(*ptep)) {
            // Send to DRAM (priority)
            ctx->found_addrs[ctx->n_found].addr = addr;
            ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
        }
        else if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
            // Add to backup list
            ctx->backup_addrs[ctx->n_backup].addr = addr;
            ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
        }
    }

    return 0;
}

// ----------------------------------------------------------------------------------


static int pte_callback_nvram_intensive(
        pte_t *ptep,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *walk)
{
    struct pte_callback_context_t * ctx =
        (struct pte_callback_context_t *) walk->private;

    // If found all save last addr
    if (ctx->n_found == ctx->n_to_find) {
        g_last_addr_nvram = addr;
        return 1;
    }

    // If page is not present, write protected, or not in NVRAM node
    if ((ptep == NULL)
    || !pte_present(*ptep)
    || !pte_write(*ptep)
    || !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
        return 0;
    }

    if(pte_young(*ptep)) {
        if (pte_dirty(*ptep)) {
            // Send to DRAM (priority)
            ctx->found_addrs[ctx->n_found].addr = addr;
            ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
            return 0;
        }

        if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
            // Add to backup list
            ctx->backup_addrs[ctx->n_backup].addr = addr;
            ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
        }
    }

    return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_switch(
        pte_t *ptep,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *walk)
{
    struct pte_callback_context_t * ctx = (struct pte_callback_context_t *) walk->private;

    // If found all save last addr
    if (ctx->n_found == ctx->n_to_find) {
        g_last_addr_nvram = addr;
        return 1;
    }

    // If page is not present, write protected, or not in NVRAM node
    if ((ptep == NULL)
    || !pte_present(*ptep)
    || !pte_write(*ptep)
    || !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
        return 0;
    }

    if(pte_young(*ptep)) {
        if (pte_dirty(*ptep)) {
            // Send to DRAM (priority)
            ctx->found_addrs[ctx->n_found].addr = addr;
            ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
        }

        // Add to backup list
        else if (ctx->n_switch_backup < (ctx->n_to_find - ctx->n_found)) {
            ctx->switch_backup_addrs[ctx->n_switch_backup].addr = addr;
            ctx->switch_backup_addrs[ctx->n_switch_backup++].pid_idx = ctx->curr_pid_idx;
        }
    }

    return 0;
}


// ----------------------------------------------------------------------------------

/*
-------------------------------------------------------------------------------

PAGE WALKERS

-------------------------------------------------------------------------------
*/

typedef int (*pte_entry_handler_t)(
        pte_t *,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *);

static int do_page_walk(
        pte_entry_handler_t pte_handler,
        struct pte_callback_context_t * ctx,
        const int last_pid,
        const unsigned long last_addr)
{
    struct mm_walk_ops mem_walk_ops = {.pte_entry = pte_handler};

    int i;
    unsigned long left = last_addr;
    unsigned long right = MAX_ADDRESS;

    pr_debug("Page walk. Mode:%p; n:%d; last_pid:%d; last_addr:%p.\n",
            pte_handler, ctx->n_to_find, last_pid, (void *) last_addr);

    // start at last_pid's last_addr, walk through all pids and finish by
    // addresses less than last_addr's last_pid; (i.e go twice through idx == last_pid)
    for (i = last_pid; i != last_pid + g_nr_pids + 1; ++i) {
        int idx = i % g_nr_pids;
        struct mm_struct *mm = g_task_items[idx]->mm;

        pr_debug("Walk iteration [%d] {pid:%d; left:%p; right: %p}\n",
                i, idx, (void *) left, (void *) right);

        ctx->curr_pid_idx = idx;

        if(mm != NULL) {
            mmap_read_lock(mm);
            g_walk_page_range(mm, left, right, &mem_walk_ops, ctx);
            mmap_read_unlock(mm);
        }

        if (ctx->n_found >= ctx->n_to_find) {
            pr_debug("Has found enough pages. Last pid is %d.", i);
            return i;
        }

        left = 0;

        if ((i + 1) % g_nr_pids == last_pid) { // second run through last_pid
            if (!last_addr) {
                break; // first run has already covered all address range.
            }
            right = last_addr + 1;
        }
    }

    pr_debug("Page walk has been completed. Found %u pages.\n", ctx->n_found);

    return last_pid;
}

int mem_walk(struct pte_callback_context_t * ctx, const int n, const int mode)
{
    pte_entry_handler_t pte_handler;
    int * last_pid = &g_last_pid_nvram;
    unsigned long * last_addr = &g_last_addr_nvram;

    ctx->n_to_find = n;
    ctx->n_backup = 0;
    ctx->n_found = 0;

    switch (mode) {
    case DRAM_MODE:
        last_pid = & g_last_pid_dram;
        last_addr = & g_last_addr_dram;
        pte_handler = pte_callback_dram;
        break;
    case NVRAM_MODE:
        pte_handler = pte_callback_nvram_force;
        break;
    case NVRAM_WRITE_MODE:
        pte_handler = pte_callback_nvram_write;
        break;
    case NVRAM_INTENSIVE_MODE:
        pte_handler = pte_callback_nvram_intensive;
        break;
    default:
        printk("Unrecognized mode.\n");
        return -1;
    }

    //pr_debug("Memory walk {mode:%d; n:%d; last_pid:%d; last_addr:%p;}\n",
    //        mode, n, *last_pid, (void *) *last_addr);
    *last_pid = do_page_walk(pte_handler, ctx, *last_pid, *last_addr);
    pr_debug("Memory walk complete. found:%d; backed-up:%d; last_pid:%d last_addr:%lx}\n",
            ctx->n_found, ctx->n_backup, *last_pid, (unsigned long)last_addr);

    if (ctx->n_found < ctx->n_to_find
    && (ctx->n_backup > 0)) {
        unsigned i = 0;
        int remaining = ctx->n_to_find - ctx->n_found;
        pr_debug("Using backup addresses (require %u, has %d)\n", remaining, ctx->n_backup);
        for (i = 0; (i < ctx->n_backup && i < remaining); ++i) {
            ctx->found_addrs[ctx->n_found].addr = ctx->backup_addrs[i].addr;
            ctx->found_addrs[ctx->n_found].pid_idx = ctx->backup_addrs[i].pid_idx;
            ++ctx->n_found;
        }
    }
    return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_clear(
        pte_t *ptep,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *walk)
{
    pte_t old_pte;
    // If  page is not present, write protected, or page is not in NVRAM node
    if ((ptep == NULL)
    || !pte_present(*ptep)
    || !pte_write(*ptep)
    || !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
        return 0;
    }

    old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
    *ptep = pte_mkold(old_pte); // unset modified bit
    *ptep = pte_mkclean(old_pte); // unset dirty bit
    ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, *ptep);

    return 0;
}

static int clear_nvram_ptes(struct pte_callback_context_t * ctx)
{
    struct mm_struct *mm;
    struct mm_walk_ops mem_walk_ops = {.pte_entry = pte_callback_nvram_clear};
    int i;

    pr_debug("Cleaning NVRAM PTEs");

    for (i = 0; i < g_nr_pids; i++) {
        mm = g_task_items[i]->mm;
        ctx->curr_pid_idx = i;
        spin_lock(&mm->page_table_lock);
        g_walk_page_range(mm, 0, MAX_ADDRESS, &mem_walk_ops, ctx);
        spin_unlock(&mm->page_table_lock);
    }

    return 0;
}

// ----------------------------------------------------------------------------------

/**
 * returns number of candidate pages
 **/
int switch_walk(struct pte_callback_context_t * ctx, u32 n)
{
    u32 nvram_found;
    u32 dram_to_find;
    u32 dram_found;

    ctx->n_found = 0;
    ctx->n_to_find = n;
    ctx->n_switch_backup = 0;

    g_last_pid_nvram = do_page_walk(pte_callback_nvram_switch, ctx, g_last_pid_nvram, g_last_addr_nvram);

    ctx->found_addrs[ctx->n_found].pid_idx = 0; // fill separator after
    if ((ctx->n_found == 0) && (ctx->n_switch_backup == 0)) {
        ctx->n_found++;
        return -1;
    }

    nvram_found = ctx->n_found; // store the number of ideal nvram pages found
    dram_to_find = min(nvram_found + ctx->n_switch_backup, n);

    ++ctx->n_found;
    ctx->n_backup = 0;
    ctx->n_to_find = ctx->n_found + dram_to_find; // try to find the same amount of dram addrs

    g_last_pid_dram = do_page_walk(pte_callback_dram, ctx, g_last_pid_dram, g_last_addr_dram);
    dram_found = ctx->n_found - nvram_found - 1;

    // found equal number of dram and nvram entries
    if (dram_found == nvram_found) {
        return 0;
    }
    else if ((dram_found < nvram_found) && (ctx->n_backup > 0)) {
        int i;
        int remaining = nvram_found - dram_found;
        int to_add;

        if (ctx->n_backup < remaining) {
            // shift left dram entries (discard excess nvram addrs)
            int i;
            int new_dram_start;
            int old_dram_start = nvram_found + 1;
            nvram_found = dram_found + ctx->n_backup; // update nvram_found and discard other entries
            new_dram_start = nvram_found + 1;
            ctx->found_addrs[nvram_found].pid_idx = 0; // fill separator after nvram pages

            for (i = 0; i < dram_found; i++) {
                ctx->found_addrs[new_dram_start + i].addr = ctx->found_addrs[old_dram_start + i].addr;
                ctx->found_addrs[new_dram_start + i].pid_idx = ctx->found_addrs[old_dram_start + i].pid_idx;
            }
            to_add = ctx->n_backup;
            ctx->n_found = new_dram_start + dram_found;
        }
        else {
            to_add = remaining;
        }
        for (i = 0; i < to_add; i++) {
            ctx->found_addrs[ctx->n_found].addr = ctx->backup_addrs[i].addr;
            ctx->found_addrs[ctx->n_found++].pid_idx = ctx->backup_addrs[i].pid_idx;
        }

    }
    else if ((nvram_found < dram_found) && (ctx->n_switch_backup > 0)) {
        unsigned remaining = dram_found - nvram_found;
        int to_add = min(ctx->n_switch_backup, remaining);
        int i;
        int old_dram_start = nvram_found + 1;
        int new_dram_start = old_dram_start + to_add;
        dram_found = nvram_found + to_add;

        // shift right dram entries
        for (i = dram_found - 1; i >= 0; --i) {
            ctx->found_addrs[new_dram_start + i].addr = ctx->found_addrs[old_dram_start + i].addr;
            ctx->found_addrs[new_dram_start + i].pid_idx = ctx->found_addrs[old_dram_start + i].pid_idx;
        }

        for (i = 0; i < to_add; ++i) {
            ctx->found_addrs[nvram_found].addr = ctx->switch_backup_addrs[i].addr;
            ctx->found_addrs[nvram_found].pid_idx = ctx->switch_backup_addrs[i].pid_idx;
            ++nvram_found;
        }
        ctx->found_addrs[nvram_found].pid_idx = 0;
        ctx->n_found = nvram_found * 2 + 1; // discard last entries
    }
    else {
        ctx->found_addrs[0].pid_idx = 0;
        ctx->n_found = 1;
    }

    return 0;
}

/*
-------------------------------------------------------------------------------

BIND/UNBIND FUNCTIONS

-------------------------------------------------------------------------------
*/


int ambix_bind_pid(pid_t pid)
{
    refresh_pids(); // ??
    if ((pid <= 0) || (pid > MAX_PID_N)) {
        pr_info("Invalid pid value in bind command.\n");
        return -1;
    }
    if (!find_target_process(pid)) {
        pr_info("Could not bind pid=%d.\n", pid);
        return -1;
    }

    pr_info("Bound pid=%d.\n", pid);
    return 0;
}

int ambix_unbind_pid(pid_t pid)
{
    // Find which task to remove
    int i;

    if ((pid <= 0) || (pid > MAX_PID_N)) {
        pr_info("Invalid pid value in unbind command.\n");
        return -1;
    }

    for (i = 0; i < g_nr_pids; i++) {
        if ((g_task_items[i] != NULL) && (g_task_items[i]->pid == pid)) {
            break;
        }
    }

    if (i == g_nr_pids) {
        pr_info("Could not unbind pid=%d.\n", pid);
        return -1;
    }

    update_pid_list(i);
    pr_info("Unbound pid=%d.\n", pid);

    refresh_pids(); 
    return 0;
}



/*
-------------------------------------------------------------------------------

MESSAGE/REQUEST PROCESSING

-------------------------------------------------------------------------------
*/

int find_candidate_pages(struct pte_callback_context_t * ctx, u32 n_pages, int mode)
{
    if (g_nr_pids == 0)
        return -1;

    switch (mode) {
    case DRAM_MODE:
    case NVRAM_MODE:
    case NVRAM_WRITE_MODE:
    case NVRAM_INTENSIVE_MODE:
        BUG_ON(n_pages > MAX_N_FIND);
        return mem_walk(ctx, n_pages, mode);
    case SWITCH_MODE:
        BUG_ON(n_pages > MAX_N_SWITCH);
        return switch_walk(ctx, n_pages);
    default:
        pr_info("Unrecognized mode.\n");
        return -1;
    }
    //ctx->found_addrs[ctx->n_found++].pid_idx = ret;
}



enum pool_t { DRAM_POOL, NVRAM_POOL };

#define K(x) ((x) << (PAGE_SHIFT - 10))
static const int * get_pool_nodes(const enum pool_t pool)
{
    switch (pool) {
    case DRAM_POOL: return DRAM_NODES;
    case NVRAM_POOL: return NVRAM_NODES;
    }

    pr_err("Unknown pool %d\n", pool);
    return ERR_PTR(-EINVAL);
}

static size_t get_pool_size(enum pool_t pool)
{
    switch (pool) {
    case DRAM_POOL: return n_dram_nodes;
    case NVRAM_POOL: return n_nvram_nodes;
    }

    pr_err("Unknown pool %d\n", pool);
    return 0;
}

static u32 get_memory_usage(enum pool_t pool)
{
    int i = 0;
    u64 totalram = 0, freeram = 0;
    const int * nodes = get_pool_nodes(pool);
    size_t size = get_pool_size(pool);
    if (IS_ERR(nodes) || size == 0) return 0;
    for (i = 0; i < size; ++i) {
        struct sysinfo inf;
        g_si_meminfo_node(&inf, nodes[i]);
        totalram += inf.totalram;
        freeram += inf.freeram;
    }
    return K(totalram - freeram) * USAGE_FACTOR / K(totalram);
}

static u64 get_memory_total(enum pool_t pool)
{
    int i = 0;
    u64 totalram = 0;
    const int * nodes = get_pool_nodes(pool);
    const size_t size = get_pool_size(pool);
    if (IS_ERR(nodes) || size == 0) return 0;
    for (i = 0; i < size; ++i) {
        struct sysinfo inf;
        g_si_meminfo_node(&inf, nodes[i]);
        totalram += inf.totalram;
    }
    return totalram * PAGE_SIZE;
}

static u64 get_node_total_pages(const int node)
{
    struct sysinfo inf;
    g_si_meminfo_node(&inf, node);
    return inf.totalram;
}

//static u32 get_memory_free_pages(enum pool_t pool)
//{
//    int i = 0;
//    u64 freeram = 0;
//    const int * nodes = get_pool_nodes(pool);
//    size_t size = get_pool_size(pool);
//    if (IS_ERR(nodes) || size == 0) return 0;
//    for (i = 0; i < size; ++i) {
//        struct sysinfo inf;
//        g_si_meminfo_node(&inf, nodes[i]);
//        freeram += inf.freeram;
//    }
//    return freeram / PAGE_SIZE;
//}

int g_switch_act = 1;
int g_thresh_act = 1;

static u32 ambix_migrate_pages(struct pte_callback_context_t *, int n_pages, int mode);

//MAIN ENTRY POINT
int ambix_check_memory(void)
{
    u32 n_migrated = 0;
    struct pte_callback_context_t * ctx = &g_context;

    pr_debug("Memory migration routine\n");

    if (g_thresh_act || g_switch_act) {
        u32 dram_usage;
        u32 nvram_usage;
        dram_usage = get_memory_usage(DRAM_POOL);
        nvram_usage = get_memory_usage(NVRAM_POOL);
        pr_debug("Current DRAM Usage: %d\n", dram_usage);
        pr_debug("Current NVRAM Usage: %d\n", nvram_usage);
    }

    refresh_pids();
    if (g_nr_pids == 0) {
        pr_debug("No bound processes...\n");
        return 0;
    }

    if (g_switch_act) {
        u64 pmm_bw = 0;
        if (PMM_MIXED) {
            pmm_bw = perf_counters_pmm_writes() + perf_counters_pmm_reads();
        }
        else {
            pmm_bw = perf_counters_pmm_writes();
        }
        pr_debug("ppm_bw: %lld, NVRAM_BW_THRESH: %d\n", pmm_bw, NVRAM_BW_THRESH);
        if (pmm_bw > NVRAM_BW_THRESH) {
            clear_nvram_ptes(ctx);
            if (get_memory_usage(DRAM_POOL) < DRAM_USAGE_TARGET) {
                u64 n_bytes;
                u32 n_pages, num;

                pr_debug("Sending....");

                n_bytes = (DRAM_USAGE_LIMIT - get_memory_usage(DRAM_POOL))
                                * get_memory_total(DRAM_POOL) / USAGE_FACTOR;

                //pr_debug("n_bytes:%lld, DRAM_USAGE_LIMIT: %lld; DRAM_USAGE: %lld; total:%lld; FACTOR:%lld\n",
                //        n_bytes,
                //        DRAM_USAGE_LIMIT,
                //        get_memory_usage(DRAM_POOL),
                //        get_memory_total(DRAM_POOL),
                //        USAGE_FACTOR);

                n_pages = min(n_bytes / PAGE_SIZE, (u64) MAX_N_FIND);

                num = ambix_migrate_pages(ctx, n_pages, NVRAM_INTENSIVE_MODE);
                if (num > 0) {
                    n_migrated += num;
                    pr_debug("NVRAM->DRAM: Sent %d intensive pages out of %d.\n", num, n_pages);
                }
            }
            else {
                u32 num;
                pr_debug("Switching....");
                num = ambix_migrate_pages(ctx, MAX_N_SWITCH, SWITCH_MODE);
                if (num > 0) {
                    n_migrated += num;
                    pr_debug("DRAM<->NVRAM: Switched %d out of %d pages.\n", num, 2 * MAX_N_SWITCH);
                }
            }
        }
    }
    if (g_thresh_act) {
        if ((get_memory_usage(DRAM_POOL)  > DRAM_USAGE_LIMIT)
        &&  (get_memory_usage(NVRAM_POOL) < NVRAM_USAGE_TARGET)) {
            u64 n_bytes = min(
                    (get_memory_usage(DRAM_POOL) - DRAM_USAGE_TARGET)
                        * get_memory_total(DRAM_POOL) / USAGE_FACTOR,
                    (NVRAM_USAGE_TARGET - get_memory_usage(NVRAM_POOL))
                         * get_memory_total(NVRAM_POOL) / USAGE_FACTOR);
            u32 n_pages = min(n_bytes / PAGE_SIZE, (u64) MAX_N_FIND);
            u32 num = ambix_migrate_pages(ctx, n_pages, DRAM_MODE);
            if (num > 0) {
                n_migrated += num;
                pr_debug("DRAM->NVRAM: Migrated %d out of %d pages.\n", num, n_pages);
            }
        }
        else if (!g_switch_act
             && (get_memory_usage(NVRAM_POOL) > NVRAM_USAGE_LIMIT)
             && (get_memory_usage(DRAM_POOL)  < DRAM_USAGE_TARGET)) {
            s64 n_bytes = min(
                    (get_memory_usage(NVRAM_POOL) - NVRAM_USAGE_TARGET)
                        * get_memory_total(NVRAM_POOL) / USAGE_FACTOR,
                    (DRAM_USAGE_TARGET - get_memory_usage(DRAM_POOL))
                        * get_memory_total(DRAM_POOL) / USAGE_FACTOR);
            u32 n_pages = n_bytes / PAGE_SIZE;
            u32 num = ambix_migrate_pages(ctx, n_pages, NVRAM_MODE);
            if (num > 0) {
                n_migrated += num;
                pr_debug("NVRAM->DRAM: Migrated %d out of %d pages.\n", num, n_pages);
            }
        }
    }
    return n_migrated;
}


static int do_migration(
        const addr_info_t found_addrs[],
        size_t n_found,
        enum pool_t destination);

static int do_switch(
        const addr_info_t found_addrs[],
        const size_t n_found)
{
    u32 sep;
    for (sep = 0; sep < n_found && found_addrs[sep].pid_idx > 0; ++sep);
    if (sep == n_found) {
        pr_debug("Can't find separator");
        return 0;
    }
    return do_migration(found_addrs, sep, NVRAM_POOL);
         + do_migration(found_addrs + sep + 1, n_found - sep - 1, DRAM_POOL);
}

/**
 * returns number of migrated pages
 */
static u32 ambix_migrate_pages(
        struct pte_callback_context_t * ctx,
        const int nr_pages,
        const int mode)
{
    pr_debug("It was requested %d page migrations\n", nr_pages);
    if (find_candidate_pages(ctx, nr_pages, mode)) {
        pr_debug("No candidates were found\n");
        return 0;
    }

    pr_debug("Found %d candidates\n", ctx->n_found);

    switch (mode) {
    case DRAM_MODE:
        return do_migration(ctx->found_addrs, ctx->n_found, NVRAM_POOL);
    case NVRAM_MODE:
    case NVRAM_WRITE_MODE:
    case NVRAM_INTENSIVE_MODE:
        return do_migration(ctx->found_addrs, ctx->n_found, DRAM_POOL);
    case SWITCH_MODE:
        return do_switch(ctx->found_addrs, ctx->n_found);
    }
    return 0;
}

static struct page *alloc_dst_page(
        struct page *page,
        unsigned long data)
{
    int nid = (int) data;
    struct page *newpage;

    newpage = __alloc_pages_node(nid,
            (GFP_HIGHUSER_MOVABLE |
             __GFP_THISNODE | __GFP_NOMEMALLOC |
             __GFP_NORETRY | __GFP_NOWARN) &
            ~__GFP_RECLAIM, 0);

    return newpage;
}
/*
 * Resolves the given address to a struct page, isolates it from the LRU and
 * puts it to the given pagelist.
 * Returns:
 *     errno - if the page cannot be found/isolated
 *     0 - when it doesn't have to be migrated because it is already on the
 *         target node
 *     1 - when it has been queued
 */

static int add_page_for_migration(
        struct mm_struct *mm,
        unsigned long addr,
        int node,
        struct list_head *pagelist)
{
    struct vm_area_struct *vma;
    struct page *page;
    unsigned int follflags;
    int err;

    mmap_read_lock(mm);
    err = -EFAULT;
    vma = find_vma(mm, addr);
    if (!vma || addr < vma->vm_start || !g_vma_migratable(vma))
        goto out;

    /* FOLL_DUMP to ignore special (like zero) pages */
    follflags = FOLL_GET | FOLL_DUMP;
    page = g_follow_page(vma, addr, follflags);

    err = PTR_ERR(page);
    if (IS_ERR(page))
        goto out;

    err = -ENOENT;
    if (!page)
        goto out;

    err = 0;
    if (page_to_nid(page) == node)
        goto out_putpage;

    err = -EACCES;
    if (PageHuge(page)) {
        if (PageHead(page)) {
            g_isolate_huge_page(page, pagelist);
            err = 1;
        }
    } else {
        struct page *head;

        head = compound_head(page);
        err = g_isolate_lru_page(head);
        if (err)
            goto out_putpage;

        err = 1;
        list_add_tail(&head->lru, pagelist);
        mod_node_page_state(page_pgdat(head),
            NR_ISOLATED_ANON + page_is_file_lru(head),
            thp_nr_pages(head));
    }
out_putpage:
    /*
     * Either remove the duplicate refcount from
     * isolate_lru_page() or drop the page ref if it was
     * not isolated.
     */
    put_page(page);
out:
    mmap_read_unlock(mm);
    return err;
}

static int do_migration(
        const addr_info_t * const found_addrs,
        const size_t n_found,
        const enum pool_t dst)
{
    LIST_HEAD(pagelist);
    size_t i;
    //size_t n_nodes = get_pool_size(dst);
    const int * node_list = get_pool_nodes(dst);
    int node = node_list[0]; //FIXME: we need to pick nodes dynamically, relaying on space availability
    int err = -EFAULT;

    //for (i = 0; i < n_nodes; ++i) {
    if (node < 0 || node >= MAX_NUMNODES || !node_state(node, N_MEMORY)) {
        pr_err("Invalid node %d", node);
        return 0;
    }

    my_lru_cache_disable();
    for (i = 0; i < n_found; ++i) {
        unsigned long addr = (unsigned long)untagged_addr(found_addrs[i].addr);
        size_t idx = found_addrs[i].pid_idx;
        struct mm_struct * mm = g_task_items[idx]->mm;
        err = add_page_for_migration(mm, addr, node, &pagelist);
        if (err > 0)
            /*Page is successfully queued for migration*/
            continue;

        break;
    }

    if (list_empty(&pagelist)) {
        err = 0;
        goto out;
    }

    err = g_migrate_pages(&pagelist, alloc_dst_page, NULL,
            (unsigned long)node, MIGRATE_SYNC, MR_SYSCALL);

    if (err) {
        err = i - err;
        g_putback_movable_pages(&pagelist);
        goto out;
    }
    err = i;

out:
    my_lru_cache_enable();
    return err;
}

/*
-------------------------------------------------------------------------------

MODULE INIT/EXIT

-------------------------------------------------------------------------------
*/

int ambix_init(void)
{
    pr_info("Initializing\n");

    g_task_items = kmalloc(sizeof(struct task_struct *) * MAX_PIDS, GFP_KERNEL);
    //found_addrs = kmalloc(sizeof(addr_info_t) * MAX_N_FIND, GFP_KERNEL);
    //backup_addrs = kmalloc(sizeof(addr_info_t) * MAX_N_FIND, GFP_KERNEL);
    //switch_backup_addrs = kmalloc(sizeof(addr_info_t) * MAX_N_SWITCH, GFP_KERNEL);

    #define M(RET, NAME, SIGNATURE) \
        if (!(g_ ## NAME = (NAME ##_t)\
                the_kallsyms_lookup_name(#NAME))) { \
            pr_err("Can't lookup '" #NAME "' function."); \
            return -1; \
        }
        #include "IMPORT.M"
    #undef M

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,5)
    if (!(g_lru_disable_count = (atomic_t *)
        the_kallsyms_lookup_name("lru_disable_count"))) {
        pr_err("Can't lookup 'lru_disable_count' variable.");
        return -1;
    }
    #endif

    // == if (!(g_alloc_migration_target = (alloc_migration_target_t)
    // ==     the_kallsyms_lookup_name("alloc_migration_target"))) {
    // ==     pr_err("Can't lookup 'alloc_migration_target' function.");
    // ==     return -1;
    // == }


    return 0;
}

void ambix_cleanup(void)
{
    pr_info("Cleaning up\n");
    // -- netlink_kernel_release(nl_sock);

    kfree(g_task_items);
    //kfree(found_addrs);
    //kfree(backup_addrs);
    //kfree(switch_backup_addrs);
    // -- kfree(nlmh_array);
}
