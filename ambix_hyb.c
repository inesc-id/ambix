/**
 * @file    placement.c
 * @author  Miguel Marques <miguel.soares.marques@tecnico.ulisboa.pt>
 * @date    12 March 2020
 * @version 0.3
 * @brief  Page walker for finding page table entries' R/M bits. Intended for the 5.6.3 Linux kernel.
 * Adapted from the code provided by Reza Karimi <r68karimi@gmail.com>
 * @see https://github.com/miguelmarques1904/ambix for a full description of the module.
 */

#define pr_fmt(fmt) "hello.PLACEMENT: " fmt

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
#include <linux/uaccess.h>

#include <linux/pagewalk.h>
#include <linux/mmzone.h> // Contains conversion between pfn and node id (NUMA node)
#include <linux/mm.h>

#include <linux/string.h>

#include "ambix.h"
#include "find_kallsyms_lookup_name.h"
#include "perf_counters.h"

// -- struct sock *nl_sock;

struct task_struct **task_items;
int n_pids = 0;

unsigned long last_addr_dram = 0;
unsigned long last_addr_nvram = 0;

int last_pid_dram = 0;
int last_pid_nvram = 0;

/* walk_page_range */
int (*the_walk_page_range)(
        struct mm_struct *mm,
        unsigned long start,
        unsigned long end,
        const struct mm_walk_ops *ops,
        void *private);

void (*the_si_meminfo_node)(struct sysinfo *val, int nid);

/*
-------------------------------------------------------------------------------

HELPER FUNCTIONS

-------------------------------------------------------------------------------
*/


static int find_target_process(pid_t pid)
{  // to find the task struct by process_name or pid
    int i;
    struct pid *pid_s;
    struct task_struct *t;

    if (n_pids >= MAX_PIDS) {
        pr_info("Managed PIDs at capacity.\n");
        return 0;
    }
    for (i=0; i < n_pids; i++) {
        if ((task_items[i] != NULL) && (task_items[i]->pid == pid)) {
            pr_info("Already managing given PID.\n");
            return 0;
        }
    }

    pid_s = find_get_pid(pid);
    if (pid_s == NULL) {
        return 0;
    }
    t = get_pid_task(pid_s, PIDTYPE_PID);
    if (t != NULL) {
        task_items[n_pids++] = t;
        return 1;
    }

    return 0;
}

static int update_pid_list(int i)
{
    int j;
    if (last_pid_dram > i) {
        last_pid_dram--;
    }
    else if (last_pid_dram == i) {
        last_addr_dram = 0;

        if (last_pid_dram == (n_pids-1)) {
            last_pid_dram = 0;
        }
    }

    if (last_pid_nvram > i) {
        last_pid_nvram--;
    }
    else if (last_pid_nvram == i) {
        last_addr_nvram = 0;

        if (last_pid_nvram == (n_pids-1)) {
            last_pid_nvram = 0;
        }
    }

    // Shift left all subsequent entries
    for (j = i; j < (n_pids - 1); j++) {
        task_items[j] = task_items[j+1];
    }

    n_pids--;

    return 0;
}

static int refresh_pids(void) {
    int i;

    for (i=0; i < n_pids; i++) {
        if((task_items[i] == NULL) || (find_get_pid(task_items[i]->pid) == NULL)) {
            update_pid_list(i);
            i--;
        }

    }

    printk(KERN_INFO "LIST AFTER REFRESH:");
    for(i=0; i<n_pids; i++) {
        printk(KERN_INFO "i:%d, pid:%d\n", i, task_items[i]->pid);
    }

    return 0;
}


// ==================================================================================
// CALLBACK FUNCTIONS
// ==================================================================================

struct pte_callback_context_t
{
    int n_found;
    int n_to_find;
    int n_backup;
    int n_switch_backup;

    int curr_pid;

    //unsigned long last_addr_dram;
    //unsigned long last_addr_nvram;
    //int last_pid_dram;
    //int last_pid_nvram;

    addr_info_t found_addrs[MAX_N_FIND];
    addr_info_t backup_addrs[MAX_N_FIND]; // prevents a second page walk
    addr_info_t switch_backup_addrs[MAX_N_SWITCH]; // for switch walk
} static g_context = {0};

static int pte_callback_mem(
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
        last_addr_dram = addr;
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
        ctx->found_addrs[ctx->n_found++].pid_retval = ctx->curr_pid;
        return 0;
    }

    if (!pte_dirty(*ptep) && (ctx->n_backup < (ctx->n_to_find - ctx->n_found))) {
        // Add to backup list
        ctx->backup_addrs[ctx->n_backup].addr = addr;
        ctx->backup_addrs[ctx->n_backup++].pid_retval = ctx->curr_pid;
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
        last_addr_nvram = addr;
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
        ctx->found_addrs[ctx->n_found++].pid_retval = ctx->curr_pid;
        return 0;
    }

    if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
        // Add to backup list
        ctx->backup_addrs[ctx->n_backup].addr = addr;
        ctx->backup_addrs[ctx->n_backup++].pid_retval = ctx->curr_pid;
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
        last_addr_nvram = addr;
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
            ctx->found_addrs[ctx->n_found++].pid_retval = ctx->curr_pid;
        }
        else if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
            // Add to backup list
            ctx->backup_addrs[ctx->n_backup].addr = addr;
            ctx->backup_addrs[ctx->n_backup++].pid_retval = ctx->curr_pid;
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
        last_addr_nvram = addr;
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
            ctx->found_addrs[ctx->n_found++].pid_retval = ctx->curr_pid;
            return 0;
        }

        if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
            // Add to backup list
            ctx->backup_addrs[ctx->n_backup].addr = addr;
            ctx->backup_addrs[ctx->n_backup++].pid_retval = ctx->curr_pid;
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
        last_addr_nvram = addr;
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
            ctx->found_addrs[ctx->n_found++].pid_retval = ctx->curr_pid;
        }

        // Add to backup list
        else if (ctx->n_switch_backup < (ctx->n_to_find - ctx->n_found)) {
            ctx->switch_backup_addrs[ctx->n_switch_backup].addr = addr;
            ctx->switch_backup_addrs[ctx->n_switch_backup++].pid_retval = ctx->curr_pid;
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

// ----------------------------------------------------------------------------------

/*
-------------------------------------------------------------------------------

PAGE WALKERS

-------------------------------------------------------------------------------
*/

typedef int (*pte_entry_handler_t)(
        pte_t *pte,
        unsigned long addr,
        unsigned long next,
        struct mm_walk *walk);

static int do_page_walk(
        pte_entry_handler_t pte_handler,
        struct pte_callback_context_t * ctx,
        int last_pid,
        unsigned long last_addr)
{
    struct mm_struct *mm;
    struct mm_walk_ops mem_walk_ops = {.pte_entry = pte_handler};
    int i;
    // begin at last_pid->last_addr
    mm = task_items[last_pid]->mm;
    ctx->curr_pid = task_items[last_pid]->pid;

    if(mm != NULL) {
        mmap_read_lock(mm);
        the_walk_page_range(mm, last_addr, MAX_ADDRESS, &mem_walk_ops, ctx);
        mmap_read_unlock(mm);
    }

    if (ctx->n_found >= ctx->n_to_find) {
        return last_pid;
    }

    for (i=last_pid+1; i<n_pids; i++) {

        mm = task_items[i]->mm;
        ctx->curr_pid = task_items[i]->pid;

        if(mm != NULL) {
            mmap_read_lock(mm);
            the_walk_page_range(mm, 0, MAX_ADDRESS, &mem_walk_ops, ctx);
            mmap_read_unlock(mm);
        }

        if (ctx->n_found >= ctx->n_to_find) {
            return i;
        }
    }

    for (i = 0; i < last_pid; i++) {
        mm = task_items[i]->mm;
        ctx->curr_pid = task_items[i]->pid;

        if(mm != NULL) {
            mmap_read_lock(mm);
            the_walk_page_range(mm, 0, MAX_ADDRESS, &mem_walk_ops, ctx);
            mmap_read_unlock(mm);
        }
        if (ctx->n_found >= ctx->n_to_find) {
            return i;
        }
    }

    // finish cycle at last_pid->last_addr
    mm = task_items[last_pid]->mm;
    ctx->curr_pid = task_items[last_pid]->pid;

    if(mm != NULL) {
        mmap_read_lock(mm);
        the_walk_page_range(mm, 0, last_addr+1, &mem_walk_ops, ctx);
        mmap_read_unlock(mm);
    }

    return last_pid;
}

int mem_walk(struct pte_callback_context_t * ctx, int n, int mode)
{
    pte_entry_handler_t pte_handler;
    int dram_walk = 0;

    refresh_pids(); // ??
    switch (mode) {
    case DRAM_MODE:
        pte_handler = pte_callback_mem;
        dram_walk = 1;
        break;
    case NVRAM_MODE:
        pte_handler = pte_callback_nvram_force;
        break;
    case NVRAM_INTENSIVE_MODE:
        pte_handler = pte_callback_nvram_intensive;
        break;
    case NVRAM_WRITE_MODE:
        pte_handler = pte_callback_nvram_write;
        break;
    default:
        printk("Unrecognized mode.\n");
        return 0;
    }

    ctx->n_to_find = n;
    ctx->n_backup = 0;

    if (dram_walk) {
        last_pid_dram = do_page_walk(pte_handler, ctx, last_pid_dram, last_addr_dram);
    }
    else {
        last_pid_nvram = do_page_walk(pte_handler, ctx, last_pid_nvram, last_addr_nvram);
    }

    if (ctx->n_found >= ctx->n_to_find) {
        return 0;
    }
    else if (ctx->n_backup > 0) {
        int remaining = ctx->n_to_find - ctx->n_found;
        int i;

        for (i=0; (i < remaining) && (i < ctx->n_backup); i++) {
            ctx->found_addrs[ctx->n_found].addr = ctx->backup_addrs[i].addr;
            ctx->found_addrs[ctx->n_found++].pid_retval = ctx->backup_addrs[i].pid_retval;
        }

        if (ctx->n_found >= ctx->n_to_find) {
            return 0;
        }
    }
    return -1;
}

int clear_walk(struct pte_callback_context_t * ctx, int mode)
{
    struct mm_struct *mm;
    struct mm_walk_ops mem_walk_ops = {.pte_entry = pte_callback_nvram_clear};

    int i;

    refresh_pids(); // ??
    for (i=0; i < n_pids; i++) {
        mm = task_items[i]->mm;
        spin_lock(&mm->page_table_lock);
        ctx->curr_pid = task_items[i]->pid;
        the_walk_page_range(mm, 0, MAX_ADDRESS, &mem_walk_ops, ctx);
        spin_unlock(&mm->page_table_lock);
    }

    return 0;
}

int switch_walk(struct pte_callback_context_t * ctx, int n)
{
    int nvram_found;
    int dram_to_find;
    int dram_found;

    refresh_pids(); // ??

    ctx->n_to_find = n;
    ctx->n_switch_backup = 0;

    last_pid_nvram = do_page_walk(pte_callback_nvram_switch, ctx, last_pid_nvram, last_addr_nvram);

    ctx->found_addrs[ctx->n_found].pid_retval = 0; // fill separator after
    if ((ctx->n_found == 0) && (ctx->n_switch_backup == 0)) {
        ctx->n_found++;
        return -1;
    }

    nvram_found = ctx->n_found; // store the number of ideal nvram pages found
    dram_to_find = int_min(nvram_found + ctx->n_switch_backup, n);
    ctx->n_found++;
    ctx->n_to_find = ctx->n_found + dram_to_find; // try to find the same amount of dram addrs
    ctx->n_backup = 0;

    last_pid_dram = do_page_walk(pte_callback_mem, ctx, last_pid_dram, last_addr_dram);
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
            ctx->found_addrs[nvram_found].pid_retval = 0; // fill separator after nvram pages

            for (i = 0; i < dram_found; i++) {
                ctx->found_addrs[new_dram_start + i].addr = ctx->found_addrs[old_dram_start + i].addr;
                ctx->found_addrs[new_dram_start + i].pid_retval = ctx->found_addrs[old_dram_start + i].pid_retval;
            }
            to_add = ctx->n_backup;
            ctx->n_found = new_dram_start + dram_found;
        }
        else {
            to_add = remaining;
        }
        for (i = 0; i < to_add; i++) {
            ctx->found_addrs[ctx->n_found].addr = ctx->backup_addrs[i].addr;
            ctx->found_addrs[ctx->n_found++].pid_retval = ctx->backup_addrs[i].pid_retval;
        }

    }
    else if ((nvram_found < dram_found) && (ctx->n_switch_backup > 0)) {
        int remaining = dram_found - nvram_found;
        int to_add = int_min(ctx->n_switch_backup, remaining);
        int i;
        int old_dram_start = nvram_found + 1;
        int new_dram_start = old_dram_start + to_add;
        dram_found = nvram_found + to_add;

        // shift right dram entries
        for (i = dram_found - 1; i >= 0; i--) {
            ctx->found_addrs[new_dram_start + i].addr = ctx->found_addrs[old_dram_start + i].addr;
            ctx->found_addrs[new_dram_start + i].pid_retval = ctx->found_addrs[old_dram_start + i].pid_retval;
        }

        for (i = 0; i < to_add; i++) {
            ctx->found_addrs[nvram_found].addr = ctx->switch_backup_addrs[i].addr;
            ctx->found_addrs[nvram_found++].pid_retval = ctx->switch_backup_addrs[i].pid_retval;
        }
        ctx->found_addrs[nvram_found].pid_retval = 0;
        ctx->n_found = nvram_found * 2 + 1; // discard last entries
    }
    else {
        ctx->found_addrs[0].pid_retval = 0;
        ctx->n_found = 1;
    }

    return 0;
}


/*
-------------------------------------------------------------------------------

BIND/UNBIND FUNCTIONS

-------------------------------------------------------------------------------
*/


int ambix_bind_pid(pid_t pid) {
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

    for (i = 0; i < n_pids; i++) {
        if ((task_items[i] != NULL) && (task_items[i]->pid == pid)) {
            break;
        }
    }

    if (i == n_pids) {
        pr_info("Could not unbind pid=%d.\n", pid);
        return -1;
    }

    update_pid_list(i);
    pr_info("Unbound pid=%d.\n", pid);

    refresh_pids(); // ??
    return 0;
}



/*
-------------------------------------------------------------------------------

MESSAGE/REQUEST PROCESSING

-------------------------------------------------------------------------------
*/



/* Valid request commands:

BIND [pid]
UNBIND [pid]
FIND [tier] [n]
*/

int ambix_find(struct pte_callback_context_t * ctx, int n_pages, int mode)
{
    int ret = -1;

    refresh_pids();
    ctx->n_found = 0;
    if (n_pids > 0) {
        int n = 0;
        switch (mode) {
            case DRAM_MODE:
            case NVRAM_MODE:
            case NVRAM_WRITE_MODE:
            case NVRAM_INTENSIVE_MODE:
                n = int_min(MAX_N_FIND, n_pages);
                ret = mem_walk(ctx, n, mode);
                break;
            case NVRAM_CLEAR:
                ret = clear_walk(ctx, mode);
                break;
            case SWITCH_MODE:
                n = int_min(MAX_N_SWITCH, n_pages);
                ret = switch_walk(ctx, n);
                break;
            default:
                pr_info("Unrecognized mode.\n");
                break;
        }
    }
    ctx->found_addrs[ctx->n_found++].pid_retval = ret;
    return ret ? ret : ctx->n_found;
}


// -- static void placement_nl_process_msg(struct sk_buff *skb) {
// --     struct nlmsghdr *nlmh;
// --     int sender_pid;
// --     struct sk_buff *skb_out;
// --     req_t *in_req;
// --     int res;
// -- 
// --     printk("Received message.\n");
// -- 
// --     // input
// --     nlmh = (struct nlmsghdr *) skb->data;
// -- 
// --     in_req = (req_t *) NLMSG_DATA(nlmh);
// --     sender_pid = nlmh->nlmsg_pid;
// -- 
// --     process_req(in_req);
// -- 
// -- 
// --     // Calculate size of the last netlink packet
// --     int last_packet_remainder = n_found % MAX_N_PER_PACKET;
// --     int last_packet_entries = last_packet_remainder;
// --     if (last_packet_remainder == 0) {
// --         last_packet_entries = MAX_N_PER_PACKET;
// --     }
// -- 
// --     int required_packets = (n_found / MAX_N_PER_PACKET) + (last_packet_remainder != 0);
// --     skb_out = nlmsg_new(NLMSG_LENGTH(MAX_PAYLOAD) * required_packets, GFP_KERNEL);
// --     if (!skb_out) {
// --         pr_err("Failed to allocate new skb.\n");
// --         return;
// --     }
// -- 
// --     int i;
// -- 
// --     for (i=0; i < required_packets-1; i++) { // process all but last packet
// --         nlmh_array[i] = nlmsg_put(skb_out, 0, 0, 0, MAX_N_PER_PACKET * sizeof(addr_info_t), NLM_F_MULTI);
// --         memset(NLMSG_DATA(nlmh_array[i]), 0, MAX_PAYLOAD);
// --         memcpy(NLMSG_DATA(nlmh_array[i]), found_addrs + i*MAX_N_PER_PACKET, MAX_PAYLOAD);
// --     }
// --     int rem_size = last_packet_entries * sizeof(addr_info_t);
// -- 
// --     nlmh_array[i] = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, rem_size, 0);
// --     memset(NLMSG_DATA(nlmh_array[i]), 0, rem_size);
// --     memcpy(NLMSG_DATA(nlmh_array[i]), found_addrs + i*MAX_N_PER_PACKET, rem_size);
// -- 
// --     NETLINK_CB(skb_out).dst_group = 0; // unicast
// -- 
// --     if (n_found == 1) {
// --         pr_info("Sending %d entry to ctl.\n", n_found);
// --     }
// --     else {
// --         pr_info("Sending %d entries to ctl in %d packets.\n", n_found, required_packets);
// --     }
// --     if ((res = nlmsg_unicast(nl_sock, skb_out, sender_pid)) < 0) {
// --             pr_info("Error sending response to ctl.\n");
// --     }
// -- }
//

enum pool_t { DRAM_POOL, NVRAM_POOL };

#define K(x) ((x) << (PAGE_SHIFT - 10))
const int * get_pool_nodes(enum pool_t pool)
{
    switch (pool) {
    case DRAM_POOL: return DRAM_NODES;
    case NVRAM_POOL: return NVRAM_NODES;
    }

    pr_err("Unknown pool %d\n", pool);
    return ERR_PTR(-EINVAL);
}

size_t get_pool_size(enum pool_t pool)
{
    switch (pool) {
    case DRAM_POOL: return n_dram_nodes;
    case NVRAM_POOL: return n_nvram_nodes;
    }

    pr_err("Unknown pool %d\n", pool);
    return 0;
}

u32 get_memory_usage(enum pool_t pool)
{
    int i = 0;
    u64 totalram = 0, freeram = 0;
    const int * nodes = get_pool_nodes(pool);
    size_t size = get_pool_size(pool);
    if (IS_ERR(nodes) || size == 0) return 0;
    for (i = 0; i < size; ++i) {
        struct sysinfo inf;
        the_si_meminfo_node(&inf, nodes[i]);
        totalram += inf.totalram;
        freeram += inf.freeram;
    }
    return K(totalram - freeram) * 100 / K(totalram);
}

u64 get_memory_total(enum pool_t pool)
{
    int i = 0;
    u64 totalram = 0;
    const int * nodes = get_pool_nodes(pool);
    size_t size = get_pool_size(pool);
    if (IS_ERR(nodes) || size == 0) return 0;
    for (i = 0; i < size; ++i) {
        struct sysinfo inf;
        the_si_meminfo_node(&inf, nodes[i]);
        totalram += inf.totalram;
    }
    return K(totalram);
}

u32 get_memory_free_pages(enum pool_t pool)
{
    int i = 0;
    u64 freeram = 0;
    const int * nodes = get_pool_nodes(pool);
    size_t size = get_pool_size(pool);
    if (IS_ERR(nodes) || size == 0) return 0;
    for (i = 0; i < size; ++i) {
        struct sysinfo inf;
        the_si_meminfo_node(&inf, nodes[i]);
        freeram += inf.freeram;
    }
    return freeram / PAGE_SIZE;
}

int g_switch_act = 1;
int g_thresh_act = 1;

int migrate_pages(struct pte_callback_context_t *, int n_pages, int mode);

//MAIN ENTRY POINT
void ambix_check_memory(void)
{
    int n_pages;
    int n_migrated = 0;
    int switch_migrated = 0;
    int thresh_migrated = 0;
    struct pte_callback_context_t * ctx = &g_context;

    if (g_thresh_act || g_switch_act) {
        u32 dram_usage;
        u32 nvram_usage;
        dram_usage = get_memory_usage(DRAM_POOL);
        nvram_usage = get_memory_usage(NVRAM_POOL);
        pr_debug("Current DRAM Usage: %d\n", dram_usage);
        pr_debug("Current NVRAM Usage: %d\n", nvram_usage);
    }

    if (g_switch_act) {
        u64 pmm_bw = 0;
        if (PMM_MIXED) {
            pmm_bw = perf_counters_pmm_bw();
        }
        else {
            pmm_bw = perf_counters_pmm_writes();
        }
        if (pmm_bw > NVRAM_BW_THRESH) {
            ambix_find(ctx, 0, NVRAM_CLEAR); //migrate_pages(0, NVRAM_CLEAR);
            if (get_memory_usage(DRAM_POOL) >= DRAM_TARGET) {
                switch_migrated = migrate_pages(ctx, MAX_N_SWITCH, SWITCH_MODE);
                if (switch_migrated > 0) {
                    pr_debug("DRAM<->NVRAM: Switched %d pages.\n", switch_migrated);
                }
            }
            else {
                long long n_bytes = (DRAM_LIMIT - get_memory_usage(DRAM_POOL)) * get_memory_total(DRAM_POOL);
                n_pages = n_bytes / PAGE_SIZE;
                n_pages = min(n_pages, MAX_N_FIND);
                switch_migrated = migrate_pages(ctx, n_pages, NVRAM_INTENSIVE_MODE);
                if (switch_migrated > 0) {
                    pr_debug("NVRAM->DRAM: Sent %d intensive pages.\n", switch_migrated);
                }
            }
        }
        n_migrated += switch_migrated;
    }
    if (g_thresh_act) {
        if ((get_memory_usage(DRAM_POOL) > DRAM_LIMIT) && (get_memory_usage(NVRAM_POOL) < NVRAM_TARGET)) {
            long long n_bytes = min(
                    (get_memory_usage(DRAM_POOL) - DRAM_TARGET) * get_memory_total(DRAM_POOL),
                    (NVRAM_TARGET - get_memory_usage(NVRAM_POOL)) * get_memory_total(NVRAM_POOL));
            n_pages = n_bytes / PAGE_SIZE;
//            pthread_mutex_lock(&placement_lock);
            thresh_migrated = migrate_pages(ctx, n_pages, DRAM_MODE);
//            pthread_mutex_unlock(&placement_lock);
            if (thresh_migrated > 0) {
                pr_debug("DRAM->NVRAM: Migrated %d out of %d pages.\n", thresh_migrated, n_pages);
            }
        }
        else if (!g_switch_act && (get_memory_usage(NVRAM_POOL) > NVRAM_LIMIT) && (get_memory_usage(DRAM_POOL) < DRAM_TARGET)) {
            long long n_bytes = min(
                    (get_memory_usage(NVRAM_POOL) - NVRAM_TARGET) * get_memory_total(NVRAM_POOL),
                    (DRAM_TARGET - get_memory_usage(DRAM_POOL)) * get_memory_total(DRAM_POOL));
            n_pages = n_bytes / PAGE_SIZE;
//            pthread_mutex_lock(&placement_lock);
            thresh_migrated = migrate_pages(ctx, n_pages, NVRAM_MODE);
//            pthread_mutex_unlock(&placement_lock);
            if (thresh_migrated > 0) {
                pr_debug("NVRAM->DRAM: Migrated %d out of %d pages.\n", thresh_migrated, n_pages);
            }
        }
    }
    n_migrated += thresh_migrated;
}


int do_migration(struct pte_callback_context_t *, int mode);
int do_switch(struct pte_callback_context_t *);

int migrate_pages(struct pte_callback_context_t * ctx, int nr_pages, int mode)
{
    int n_found = ambix_find(ctx, nr_pages, mode);
    if (n_found < 0) {
        return 0;
    }
    switch (mode) {
    case DRAM_MODE:
        return do_migration(ctx, DRAM_MODE);
    case NVRAM_MODE:
    case NVRAM_INTENSIVE_MODE:
    case NVRAM_WRITE_MODE:
        return do_migration(ctx, NVRAM_MODE);
    case SWITCH_MODE:
        return do_switch(ctx);
    }
    return 0;
}

int do_switch(struct pte_callback_context_t * ctx)
{
    return 0;
//    void **addr_dram = malloc(sizeof(unsigned long) * n_found);
//    int *dest_nodes_dram = malloc(sizeof(int) * n_found);
//    void **addr_nvram = malloc(sizeof(unsigned long) * n_found);
//    int *dest_nodes_nvram = malloc(sizeof(int) * n_found);
//    int *status = malloc(sizeof(int) * n_found);
//
//    for (int i=0; i < n_found; i++) {
//        status[i] = -123;
//    }
//
//    int dram_migrated = 0;
//    int nvram_migrated = 0;
//    int dram_e = 0; // counts failed migrations
//    int nvram_e = 0; // counts failed migrations
//
//    int dram_free = 1;
//    int nvram_free = 1;
//
//    while ((((dram_migrated + dram_e) < n_found) || ((nvram_migrated + nvram_e) < n_found)) && (dram_free || nvram_free)) {
//        // DRAM -> NVRAM
//        int old_n_processed = dram_migrated + dram_e;
//        int dram_processed = old_n_processed;
//
//        for (int i=0; (i < n_nvram_nodes) && (dram_processed < n_found); i++) {
//            int curr_node = NVRAM_NODES[i];
//
//            long long node_fr = 0;
//            numa_node_size64(curr_node, &node_fr);
//            int n_avail_pages = node_fr / page_size;
//
//            int j=0;
//            for (; (j < n_avail_pages) && (j+dram_processed < n_found); j++) {
//                addr_dram[dram_processed+j] = (void *) candidates[n_found+1+j].addr;
//                dest_nodes_nvram[dram_processed+j] = curr_node;
//            }
//
//            dram_processed += j;
//        }
//        if (old_n_processed < dram_processed) {
//            // Send processed pages to NVRAM
//            int n_migrated, i;
//            dram_free = 1;
//
//            for (n_migrated=0, i=0; n_migrated < dram_processed; n_migrated+=i) {
//                int curr_pid;
//                curr_pid = candidates[n_found+1+n_migrated].pid_retval;
//
//                for (i=1; (candidates[n_found+1+n_migrated+i].pid_retval == curr_pid) && (n_migrated+i < dram_processed); i++);
//                void **addr_displacement = addr_dram + n_migrated;
//                int *dest_nodes_displacement = dest_nodes_nvram + n_migrated;
//                if (numa_move_pages(curr_pid, (unsigned long) i, addr_displacement, dest_nodes_displacement, status, 0)) {
//                    // Migrate all and output addresses that could not migrate
//                    for (int j=0; j < i; j++) {
//                        if (numa_move_pages(curr_pid, 1, addr_displacement + j, dest_nodes_displacement + j, status, 0)) {
//                            printf("Error migrating DRAM/MEM addr: %ld, pid: %d\n", (unsigned long) *(addr_displacement + j), curr_pid);
//                            dram_e++;
//                        }
//                    }
//                }
//            }
//        }
//        else {
//            dram_free = 0;
//        }
//
//        dram_migrated = dram_processed - dram_e;
//
//        // NVRAM -> DRAM
//        old_n_processed = nvram_migrated + nvram_e;
//        int nvram_processed = old_n_processed;
//
//        for (int i=0; (i < n_dram_nodes) && (nvram_processed < n_found); i++) {
//            int curr_node = DRAM_NODES[i];
//
//            long long node_fr = 0;
//            numa_node_size64(curr_node, &node_fr);
//            int n_avail_pages = node_fr / page_size;
//
//            int j=0;
//            for (; (j < n_avail_pages) && (j+nvram_processed < n_found); j++) {
//                addr_nvram[nvram_processed+j] = (void *) candidates[nvram_processed+j].addr;
//                dest_nodes_dram[nvram_processed+j] = curr_node;
//            }
//
//            nvram_processed += j;
//        }
//
//        if (old_n_processed < nvram_processed) {
//            // Send processed pages to DRAM
//            int n_migrated, i;
//            nvram_free = 1;
//
//            for (n_migrated=0, i=0; n_migrated < nvram_processed; n_migrated+=i) {
//                int curr_pid;
//                curr_pid=candidates[n_migrated].pid_retval;
//
//                for (i=1; (candidates[n_migrated+i].pid_retval == curr_pid) && (n_migrated+i < nvram_processed); i++);
//                void **addr_displacement = addr_nvram + n_migrated;
//                int *dest_nodes_displacement = dest_nodes_dram + n_migrated;
//                if (numa_move_pages(curr_pid, (unsigned long) i, addr_displacement, dest_nodes_displacement, status, 0)) {
//                    // Migrate all and output addresses that could not migrate
//                    for (int j=0; j < i; j++) {
//                        if (numa_move_pages(curr_pid, 1, addr_displacement + j, dest_nodes_displacement + j, status, 0)) {
//                            printf("Error migrating NVRAM addr: %ld, pid: %d\n", (unsigned long) *(addr_displacement + j), curr_pid);
//                            nvram_e++;
//                        }
//                    }
//                }
//            }
//        }
//        else {
//            nvram_free = 0;
//        }
//
//        nvram_migrated = nvram_processed - nvram_e;
//    }
//
//    free(addr_dram);
//    free(addr_nvram);
//    free(dest_nodes_dram);
//    free(dest_nodes_nvram);
//    free(status);
//
//    return dram_migrated + nvram_migrated;
}

int do_migration(
        struct pte_callback_context_t * ctx,
        int mode)
{
//    void **addr = malloc(sizeof(unsigned long) * n_found);
//    int *dest_nodes = malloc(sizeof(int) * n_found);
//    int *status = malloc(sizeof(int) * n_found);

    const int *node_list;
    int n_nodes;

    int i = 0;
    int n_processed = 0;
    enum pool_t pool;
    if (mode == DRAM_MODE) {
        node_list = NVRAM_NODES;
        n_nodes = n_nvram_nodes;
        pool = NVRAM_POOL;
    }
    else {
        node_list = DRAM_NODES;
        n_nodes = n_dram_nodes;
        pool = DRAM_POOL;
    }

    //for (int i=0; i< n_found; i++) {
    //    status[i] = -123;
    //}

//    for (i = 0; (i < n_nodes) && (n_processed < ctx->n_found); i++) {
//        int curr_node = node_list[i];
//
//        int n_avail_pages = get_memory_free_pages(pool);
//        //int n_avail_pages = free_space_pages(curr_node);
//
//        int j=0;
//        for (; (j < n_avail_pages) && (n_processed+j < n_found); j++) {
//            addr[n_processed+j] = (void *) candidates[n_processed+j].addr;
//            dest_nodes[n_processed+j] = curr_node;
//        }
//
//        n_processed += j;
//    }
//    int n_migrated, i;
//    int e = 0; // counts failed migrations
//
//    for (n_migrated=0, i=0; n_migrated < n_processed; n_migrated+=i) {
//        int curr_pid;
//        curr_pid=candidates[n_migrated].pid_retval;
//
//        for (i=1; (candidates[n_migrated+i].pid_retval == curr_pid) && (n_migrated+i < n_processed); i++);
//
//        void **addr_displacement = addr + n_migrated;
//        int *dest_nodes_displacement = dest_nodes + n_migrated;
//        if (move_pages(curr_pid, (unsigned long) i, addr_displacement, dest_nodes_displacement, status, 0)) {
//            // Migrate all and output addresses that could not migrate
//            for (int j=0; j < i; j++) {
//                if (move_pages(curr_pid, 1, addr_displacement + j, dest_nodes_displacement + j, status, 0)) {
//                    printf("Error migrating addr: %ld, pid: %d\n", (unsigned long) *(addr_displacement + j), curr_pid);
//                    e++;
//                }
//            }
//        }
//    }
//
//    free(addr);
//    free(dest_nodes);
//    free(status);
//    return n_migrated - e;
    return 0;
}

/*
-------------------------------------------------------------------------------

MODULE INIT/EXIT

-------------------------------------------------------------------------------
*/


int ambix_init(void)
{
    pr_info("Initializing\n");

    task_items = kmalloc(sizeof(struct task_struct *) * MAX_PIDS, GFP_KERNEL);
    //found_addrs = kmalloc(sizeof(addr_info_t) * MAX_N_FIND, GFP_KERNEL);
    //backup_addrs = kmalloc(sizeof(addr_info_t) * MAX_N_FIND, GFP_KERNEL);
    //switch_backup_addrs = kmalloc(sizeof(addr_info_t) * MAX_N_SWITCH, GFP_KERNEL);

    the_walk_page_range = (int (*)(
                struct mm_struct *,
                unsigned long start,
                unsigned long end,
                const struct mm_walk_ops *,
                void *private))
        the_kallsyms_lookup_name("walk_page_range");

    the_si_meminfo_node = (void (*)(
                struct sysinfo *,
                int nid))
        the_kallsyms_lookup_name("si_meminfo_node");

    if (!the_walk_page_range) {
        pr_err("Can't lookup 'walk_page_range' function.");
        return -1;
    }

    if (!the_si_meminfo_node) {
        pr_err("Can't lookup 'si_meminfo_node' function.");
        return -1;
    }

    return 0;
}

void ambix_cleanup(void) {
    pr_info("Cleaning up\n");
    // -- netlink_kernel_release(nl_sock);

    kfree(task_items);
    //kfree(found_addrs);
    //kfree(backup_addrs);
    //kfree(switch_backup_addrs);
    // -- kfree(nlmh_array);
}
