/**
 * @file    placement.c
 * @author  INESC-ID
 * @date    26 jul 2023
 * @version 2.1.1
 * @brief  Page walker for finding page table entries' r/m bits. Intended for
 * the 5.10.0 linux kernel. Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code provided by reza
 * karimi <r68karimi@gmail.com>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#define pr_fmt(fmt) "ambix.PLACEMENT: " fmt

#include <generated/utsrelease.h>
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
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/timekeeping.h>

#include <linux/huge_mm.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/mmzone.h> // Contains conversion between pfn and node id (NUMA node)
#include <linux/mutex.h>
#include <linux/pagewalk.h>
#include <linux/string.h>

#include "config.h"
#include "find_kallsyms_lookup_name.h"
#include "perf_counters.h"
#include "placement.h"
#include "tsc.h"

#define SEPARATOR 0xbad
#define CLEAR_PTE_THRESHOLD 501752

#define MAX_N_FIND 131071U
#define MAX_N_SWITCH MAX_N_FIND
#define PMM_MIXED 1

#define MAX_PIDS                                                               \
  20 // sets the number of PIDs that can be bound to Ambix at any given time

#define IS_64BIT (sizeof(void *) == 8)
#define MAX_ADDRESS                                                            \
  (IS_64BIT                                                                    \
       ? 0xFFFF880000000000UL                                                  \
       : 0xC0000000UL) // Max user-space addresses for the x86 architecture

#define DRAM_MODE 0
#define NVRAM_MODE 1
#define NVRAM_INTENSIVE_MODE 2
#define SWITCH_MODE 3
#define NVRAM_WRITE_MODE 5

#define K(x) ((x) << (PAGE_SHIFT - 10))

// Node definition: DRAM nodes' (memory mode) ids must always be a lower value
// than NVRAM nodes' ids due to the memory policy set in client-placement.c
// CHANGE THIS ACCORDING TO HARDWARE CONFIGURATION
static const int DRAM_NODES[] = _DRAM_NODES;
static const int NVRAM_NODES[] = _NVRAM_NODES;

static const int n_dram_nodes = ARRAY_SIZE(DRAM_NODES);
static const int n_nvram_nodes = ARRAY_SIZE(NVRAM_NODES);

unsigned long g_last_addr_dram = 0;
unsigned long g_last_addr_nvram = 0;

int g_last_pid_dram = 0;
int g_last_pid_nvram = 0;

unsigned long long dram_usage = 0;
unsigned long long nvram_usage = 0;

unsigned long long pages_walked = 0;
unsigned long last_addr_clear = 0;
int migration_type = 0;

#define M(RET, NAME, SIGNATURE)                                                \
  typedef RET(*NAME##_t) SIGNATURE;                                            \
  NAME##_t g_##NAME
#include "IMPORT.M"
#undef M

typedef struct addr_info {
  unsigned long addr;
  size_t pid_idx;
} addr_info_t;

struct ambix_proc_t {
  struct pid *__pid;
  unsigned long start_addr;
  unsigned long end_addr;
  unsigned long allocation_site;
  unsigned long size;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 5)
/**
 * Can't import inline functions, have to duplicate:
 */
atomic_t *g_lru_disable_count;

static inline bool my_lru_cache_disable(void) {
  return atomic_read(g_lru_disable_count);
}

static inline void my_lru_cache_enable(void) {
  atomic_dec(g_lru_disable_count);
}
#else
static inline bool my_lru_cache_disable(void) {
  g_lru_add_drain_all();
  return true;
}
static inline void my_lru_cache_enable(void) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 6)
#define thp_nr_pages(head) hpage_nr_pages(head)
#endif

/*
-------------------------------------------------------------------------------

HELPER FUNCTIONS

-------------------------------------------------------------------------------
*/

int contains(int value, int mode) {
  const int *array;
  int size, i;

  if (mode == NVRAM_MODE) {
    array = NVRAM_NODES;
    size = n_nvram_nodes;
  } else {
    array = DRAM_NODES;
    size = n_dram_nodes;
  }
  for (i = 0; i < size; i++) {
    if (array[i] == value) {
      return 1;
    }
  }
  return 0;
}

/*
-------------------------------------------------------------------------------

BIND/UNBIND FUNCTIONS

-------------------------------------------------------------------------------
*/

static struct ambix_proc_t PIDs[MAX_PIDS];
size_t PIDs_size = 0;

static DEFINE_MUTEX(PIDs_mtx);
static DEFINE_MUTEX(USAGE_mtx);

int ambix_bind_pid_constrained(const pid_t nr, unsigned long start_addr,
                               unsigned long end_addr,
                               unsigned long allocation_site,
                               unsigned long size) {
  struct pid *p = NULL;
  struct mutex *m = NULL;
  size_t i;
  int rc = 0;
  int index = 0;

  p = find_get_pid(nr);
  if (!p) {
    pr_warn("Invalid pid value (%d): can't find pid.\n", nr);
    rc = -1;
    goto release_return;
  }

  mutex_lock(&PIDs_mtx);
  m = &PIDs_mtx;

  if (PIDs_size == ARRAY_SIZE(PIDs)) {
    pr_warn("Managed PIDs at capacity.\n");
    rc = -1;
    goto release_return;
  }

  for (i = 0; i < PIDs_size; ++i) {
    if (PIDs[i].__pid == p && PIDs[i].start_addr == start_addr &&
        PIDs[i].end_addr == end_addr) {
      pr_info("Already managing given PID.\n");
      rc = -1;
      goto release_return;
    }
  }

  index = PIDs_size++;
  PIDs[index].__pid = p;
  PIDs[index].start_addr = start_addr;
  PIDs[index].end_addr = end_addr;
  PIDs[index].allocation_site = allocation_site;
  PIDs[index].size = size;
  p = NULL;
  pr_info("Bound pid=%d with start_addr=%lx and end_addr=%lx.\n", nr,
          start_addr, end_addr);

release_return:
  if (m)
    mutex_unlock(m);
  if (p)
    put_pid(p);
  return rc;
}

int ambix_bind_pid(const pid_t nr) {
  return ambix_bind_pid_constrained(nr, 0, MAX_ADDRESS, 0, 0);
}

int ambix_unbind_pid(const pid_t nr) {
  struct pid *p = NULL;
  struct mutex *m = NULL;

  size_t i;
  int rc = 0;

  mutex_lock(&PIDs_mtx);
  m = &PIDs_mtx;

  for (i = 0; i < PIDs_size; ++i) {
    if (pid_nr(PIDs[i].__pid) == nr) {
      p = PIDs[i].__pid;
      if (PIDs_size > 0) {
        PIDs[i] = PIDs[--PIDs_size];
      }
      // as now there can be multiple entries for each pid (each with
      // a different range), we iterate the whole list
      // pr_info("Unbound pid=%d.\n", nr);
      // goto release_return;
    }
  }

  if (m)
    mutex_unlock(m);
  if (p)
    put_pid(p);
  return rc;
}

int ambix_unbind_range_pid(const pid_t nr, unsigned long start,
                           unsigned long end) {
  struct pid *p = NULL;
  struct mutex *m = NULL;

  size_t i;
  int rc = 0;

  mutex_lock(&PIDs_mtx);
  m = &PIDs_mtx;

  for (i = 0; i < PIDs_size; ++i) {
    if (pid_nr(PIDs[i].__pid) == nr && start == PIDs[i].start_addr &&
        end == PIDs[i].end_addr) {
      p = PIDs[i].__pid;
      if (PIDs_size > 0) {
        PIDs[i] = PIDs[--PIDs_size];
      }
      pr_info("Unbound pid=%d.\n", nr);
      goto release_return;
    }
  }

release_return:
  if (m)
    mutex_unlock(m);
  if (p)
    put_pid(p);
  return rc;
}

void refresh_pids(void)
// NB! should be called under PIDs_mtx lock
{
  size_t i;
  for (i = 0; i < PIDs_size; ++i) {
    struct task_struct *t = get_pid_task(PIDs[i].__pid, PIDTYPE_PID);
    if (t) {
      put_task_struct(t);
      continue;
    }
    pr_info("Process %d has gone.\n", pid_nr(PIDs[i].__pid));
    put_pid(PIDs[i].__pid);
    PIDs[i] = PIDs[--PIDs_size];
  }
}

// ==================================================================================
// CALLBACK FUNCTIONS
// ==================================================================================

struct pte_callback_context_t {
  u32 n_found;
  u32 n_to_find;
  u32 n_backup;
  u32 n_switch_backup;

  size_t curr_pid_idx;

  addr_info_t found_addrs[MAX_N_FIND];
  addr_info_t backup_addrs[MAX_N_FIND];          // prevents a second page walk
  addr_info_t switch_backup_addrs[MAX_N_SWITCH]; // for switch walk
} static g_context = {0};

static int pte_callback_usage(pte_t *ptep, unsigned long addr,
                              unsigned long next, struct mm_walk *walk) {

  if (pte_present(*ptep) && contains(pfn_to_nid(pte_pfn(*ptep)), DRAM_MODE)) {
    dram_usage += 4; // 4KiB per page, should change to a variable in the future
  } else if (pte_present(*ptep) &&
             contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
    nvram_usage += 4;
  }

  return 0;
}

static void walk_ranges_usage(void) {
  struct task_struct *t = NULL;
  struct mm_walk_ops mem_walk_ops = {.pte_entry = pte_callback_usage};
  int i;
  pr_info("Walking page ranges to get memory usage");

  dram_usage = 0;
  nvram_usage = 0;

  mutex_lock(&USAGE_mtx);
  for (i = 0; i < PIDs_size; i++) {
    t = get_pid_task(PIDs[i].__pid, PIDTYPE_PID);
    if (!t) {
      pr_warn("Can't resolve task (%d).\n", pid_nr(PIDs[i].__pid));
      continue;
    }
    spin_lock(&t->mm->page_table_lock);
    g_walk_page_range(t->mm, PIDs[i].start_addr, PIDs[i].end_addr,
                      &mem_walk_ops, NULL);
    spin_unlock(&t->mm->page_table_lock);
    put_task_struct(t);
  }
  mutex_unlock(&USAGE_mtx);
}

static int pte_callback_dram(pte_t *ptep, unsigned long addr,
                             unsigned long next, struct mm_walk *walk) {
  struct pte_callback_context_t *ctx =
      (struct pte_callback_context_t *)walk->private;

  pte_t old_pte;

  // If found all, save last addr
  if (ctx->n_found == ctx->n_to_find) {
    pr_debug("Dram callback: found enough pages, storing last addr %lx\n",
             addr);
    g_last_addr_dram = addr;
    return 1;
  }

  // If page is not present, write protected, or not in DRAM node
  if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
      !contains(pfn_to_nid(pte_pfn(*ptep)), DRAM_MODE)) {
    return 0;
  }

  if (!pte_young(*ptep)) {
    // Send to NVRAM
    ctx->found_addrs[ctx->n_found].addr = addr;
    ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
    return 0;
  }

  if (!pte_dirty(*ptep) && (ctx->n_backup < (ctx->n_to_find - ctx->n_found))) {
    // Add to backup list
    ctx->backup_addrs[ctx->n_backup].addr = addr;
    ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
  }

  old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
  *ptep = pte_mkold(old_pte);   // unset modified bit
  *ptep = pte_mkclean(old_pte); // unset dirty bit
  ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, *ptep);
  return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_force(pte_t *ptep, unsigned long addr,
                                    unsigned long next, struct mm_walk *walk) {
  struct pte_callback_context_t *ctx =
      (struct pte_callback_context_t *)walk->private;

  pte_t old_pte;

  // If found all save last addr
  if (ctx->n_found == ctx->n_to_find) {
    g_last_addr_nvram = addr;
    return 1;
  }

  // If page is not present, write protected, or not in NVRAM node
  if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
      !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
    return 0;
  }

  if (pte_young(*ptep) && pte_dirty(*ptep)) {
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
  *ptep = pte_mkold(old_pte);   // unset modified bit
  *ptep = pte_mkclean(old_pte); // unset dirty bit
  ptep_modify_prot_commit(walk->vma, addr, ptep, old_pte, *ptep);

  return 0;
}

// ----------------------------------------------------------------------------------

// used only for debug in ctl (NVRAM_WRITE_MODE)
static int pte_callback_nvram_write(pte_t *ptep, unsigned long addr,
                                    unsigned long next, struct mm_walk *walk) {
  struct pte_callback_context_t *ctx =
      (struct pte_callback_context_t *)walk->private;

  // If found all save last addr
  if (ctx->n_found == ctx->n_to_find) {
    g_last_addr_nvram = addr;
    return 1;
  }

  // If page is not present, write protected, or not in NVRAM node
  if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
      !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
    return 0;
  }

  if (pte_dirty(*ptep)) {
    if (pte_young(*ptep)) {
      // Send to DRAM (priority)
      ctx->found_addrs[ctx->n_found].addr = addr;
      ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
    } else if (ctx->n_backup < (ctx->n_to_find - ctx->n_found)) {
      // Add to backup list
      ctx->backup_addrs[ctx->n_backup].addr = addr;
      ctx->backup_addrs[ctx->n_backup++].pid_idx = ctx->curr_pid_idx;
    }
  }

  return 0;
}

// ----------------------------------------------------------------------------------

static int pte_callback_nvram_intensive(pte_t *ptep, unsigned long addr,
                                        unsigned long next,
                                        struct mm_walk *walk) {
  struct pte_callback_context_t *ctx =
      (struct pte_callback_context_t *)walk->private;

  // If found all save last addr
  if (ctx->n_found == ctx->n_to_find) {
    g_last_addr_nvram = addr;
    return 1;
  }

  // If page is not present, write protected, or not in NVRAM node
  if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
      !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
    return 0;
  }

  if (pte_young(*ptep)) {
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

static int pte_callback_nvram_switch(pte_t *ptep, unsigned long addr,
                                     unsigned long next, struct mm_walk *walk) {
  struct pte_callback_context_t *ctx =
      (struct pte_callback_context_t *)walk->private;

  // If found all save last addr
  if (ctx->n_found == ctx->n_to_find) {
    g_last_addr_nvram = addr;
    return 1;
  }

  // If page is not present, write protected, or not in NVRAM node
  if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
      !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
    return 0;
  }

  if (pte_young(*ptep)) {
    if (pte_dirty(*ptep)) {
      // Send to DRAM (priority)
      ctx->found_addrs[ctx->n_found].addr = addr;
      ctx->found_addrs[ctx->n_found++].pid_idx = ctx->curr_pid_idx;
    }

    // Add to backup list
    else if (ctx->n_switch_backup < (ctx->n_to_find - ctx->n_found)) {
      ctx->switch_backup_addrs[ctx->n_switch_backup].addr = addr;
      ctx->switch_backup_addrs[ctx->n_switch_backup++].pid_idx =
          ctx->curr_pid_idx;
    }
  }

  return 0;
}

static int pte_callback_nvram_clear(pte_t *ptep, unsigned long addr,
                                    unsigned long next, struct mm_walk *walk) {
  pte_t old_pte;
  pages_walked++;

  if (pages_walked > CLEAR_PTE_THRESHOLD) {
    last_addr_clear = addr;
    return 1;
  }
  // If  page is not present, write protected, or page is not in NVRAM node
  if ((ptep == NULL) || !pte_present(*ptep) || !pte_write(*ptep) ||
      !contains(pfn_to_nid(pte_pfn(*ptep)), NVRAM_MODE)) {
    return 0;
  }

  old_pte = ptep_modify_prot_start(walk->vma, addr, ptep);
  *ptep = pte_mkold(old_pte);   // unset modified bit
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

typedef int (*pte_entry_handler_t)(pte_t *, unsigned long addr,
                                   unsigned long next, struct mm_walk *);

static const char *print_mode(pte_entry_handler_t h) {
  if (h == pte_callback_nvram_switch)
    return "NVRAM-switch";
  else if (h == pte_callback_nvram_intensive)
    return "NVRAM-intensive";
  else if (h == pte_callback_nvram_write)
    return "NVRAM-write";
  else if (h == pte_callback_nvram_force)
    return "NVRAM-force";
  else if (h == pte_callback_nvram_clear)
    return "NVRAM-clear";
  else if (h == pte_callback_dram)
    return "DRAM";
  else
    return "Unknown";
}

static int do_page_walk(pte_entry_handler_t pte_handler,
                        struct pte_callback_context_t *ctx,
                        const int lst_pid_idx, const unsigned long last_addr) {
  struct mm_walk_ops mem_walk_ops = {.pte_entry = pte_handler};

  int i;
  unsigned long left = last_addr;
  unsigned long right = PIDs[lst_pid_idx].end_addr;

  pr_debug("Page walk. Mode:%s; n:%d/%d; last_pid:%d(%d); last_addr:%lx.\n",
           print_mode(pte_handler), ctx->n_found, ctx->n_to_find,
           pid_nr(PIDs[lst_pid_idx].__pid), lst_pid_idx, last_addr);

  // start at lst_pid_idx's last_addr, walk through all pids and finish by
  // addresses less than last_addr's lst_pid_idx; (i.e go twice through idx ==
  // lst_pid_idx)
  for (i = lst_pid_idx; i != lst_pid_idx + PIDs_size + 1; ++i) {
    int idx = i % PIDs_size;
    int next_idx = (idx + 1) % PIDs_size;
    struct task_struct *t = get_pid_task(PIDs[idx].__pid, PIDTYPE_PID);
    if (!t) {
      continue;
    }

    pr_debug("Walk iteration [%d] {pid:%d(%d); left:%lx; right: %lx}\n", i,
             pid_nr(PIDs[idx].__pid), idx, left, right);

    if (t->mm != NULL) {
      mmap_read_lock(t->mm);
      ctx->curr_pid_idx = idx;
      g_walk_page_range(t->mm, left, right, &mem_walk_ops, ctx);
      mmap_read_unlock(t->mm);
    }
    put_task_struct(t);

    if (ctx->n_found >= ctx->n_to_find) {
      pr_debug("Has found enough (%u) pages. Last pid is %d(%d).", ctx->n_found,
               pid_nr(PIDs[idx].__pid), idx);
      return idx;
    }

    // TODO check this (MIGRATING UNBOUND PAGES)
    // PIDs[idx].start_addr

    left = PIDs[next_idx].start_addr;

    if ((i + 1) % PIDs_size == lst_pid_idx) { // second run through lst_pid_idx
      if (!last_addr) {
        break; // first run has already covered all address range.
      }
      right = last_addr; // + page?
    }
  }

  pr_debug("Page walk has completed. Found %u of %u pages.\n", ctx->n_found,
           ctx->n_to_find);

  return lst_pid_idx;
}

/**
 * returns 0 if success, -1 if error occurs
 **/
int mem_walk(struct pte_callback_context_t *ctx, const int n, const int mode) {
  pte_entry_handler_t pte_handler;
  int *last_pid_idx = &g_last_pid_nvram;
  unsigned long *last_addr = &g_last_addr_nvram;

  ctx->n_to_find = n;
  ctx->n_backup = 0;
  ctx->n_found = 0;

  switch (mode) {
  case DRAM_MODE:
    last_pid_idx = &g_last_pid_dram;
    last_addr = &g_last_addr_dram;
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

  *last_pid_idx = do_page_walk(pte_handler, ctx, *last_pid_idx, *last_addr);
  pr_debug("Memory walk complete. found:%d; backed-up:%d; last_pid:%d(%d) "
           "last_addr:%lx;\n",
           ctx->n_found, ctx->n_backup, pid_nr(PIDs[*last_pid_idx].__pid),
           *last_pid_idx, *last_addr);

  if (ctx->n_found < ctx->n_to_find && (ctx->n_backup > 0)) {
    unsigned i = 0;
    int remaining = ctx->n_to_find - ctx->n_found;
    pr_debug("Using backup addresses (require %u, has %d)\n", remaining,
             ctx->n_backup);
    for (i = 0; (i < ctx->n_backup && i < remaining); ++i) {
      ctx->found_addrs[ctx->n_found].addr = ctx->backup_addrs[i].addr;
      ctx->found_addrs[ctx->n_found].pid_idx = ctx->backup_addrs[i].pid_idx;
      ++ctx->n_found;
    }
  }
  return 0;
}

// ----------------------------------------------------------------------------------

static int clear_nvram_ptes(struct pte_callback_context_t *ctx) {
  struct task_struct *t = NULL;
  struct mm_walk_ops mem_walk_ops = {.pte_entry = pte_callback_nvram_clear};
  int i;
  unsigned long prev_last_addr = 0;

  pr_debug("Cleaning NVRAM PTEs");

  for (i = 0; i < PIDs_size; i++) {
    t = get_pid_task(PIDs[i].__pid, PIDTYPE_PID);
    if (!t) {
      pr_warn("Can't resolve task (%d).\n", pid_nr(PIDs[i].__pid));
      continue;
    }
    ctx->curr_pid_idx = i;
    spin_lock(&t->mm->page_table_lock);
    do {
      pr_info("prev_last_addr = %lu, last_addr_clear = %lu\n", prev_last_addr,
              last_addr_clear);
      prev_last_addr = last_addr_clear;
      pages_walked = 0;
      g_walk_page_range(t->mm, last_addr_clear, MAX_ADDRESS, &mem_walk_ops,
                        ctx);
    } while (prev_last_addr != last_addr_clear);
    spin_unlock(&t->mm->page_table_lock);
    put_task_struct(t);
  }
  return 0;
}

// ----------------------------------------------------------------------------------

/**
 * return 0 if success, (-1 otherwise)
 **/
int switch_walk(struct pte_callback_context_t *ctx, u32 n) {
  u32 nvram_found;
  u32 dram_to_find;
  u32 dram_found;

  ctx->n_found = 0;
  ctx->n_to_find = n;
  ctx->n_switch_backup = 0;

  g_last_pid_nvram = do_page_walk(pte_callback_nvram_switch, ctx,
                                  g_last_pid_nvram, g_last_addr_nvram);

  ctx->found_addrs[ctx->n_found++].pid_idx = SEPARATOR; // fill separator after
  if ((ctx->n_found == 1) && (ctx->n_switch_backup == 0)) {
    ctx->n_found++;
    return -1;
  }

  nvram_found = ctx->n_found - 1; // store the number of ideal nvram pages found
  dram_to_find = min(nvram_found + ctx->n_switch_backup, n);

  ctx->n_backup = 0;
  ctx->n_to_find =
      ctx->n_found + dram_to_find; // try to find the same amount of dram addrs

  g_last_pid_dram =
      do_page_walk(pte_callback_dram, ctx, g_last_pid_dram, g_last_addr_dram);
  dram_found = ctx->n_found - 1 /*separator*/ - nvram_found;

  // found equal number of dram and nvram entries
  if (dram_found == nvram_found) {
    return 0;
  }
  if ((dram_found < nvram_found) && (ctx->n_backup > 0)) {
    int i;
    int remaining = nvram_found - dram_found;
    int to_add = remaining;

    if (ctx->n_backup < remaining) {
      // shift left dram entries (discard excess nvram addrs)
      int i;
      int new_dram_start;
      int old_dram_start = nvram_found + 1;
      nvram_found =
          dram_found +
          ctx->n_backup; // update nvram_found and discard other entries
      new_dram_start = nvram_found + 1;
      ctx->found_addrs[nvram_found].pid_idx =
          SEPARATOR; // fill separator after nvram pages

      for (i = 0; i < dram_found; i++) {
        ctx->found_addrs[new_dram_start + i].addr =
            ctx->found_addrs[old_dram_start + i].addr;
        ctx->found_addrs[new_dram_start + i].pid_idx =
            ctx->found_addrs[old_dram_start + i].pid_idx;
      }
      to_add = ctx->n_backup;
      ctx->n_found = new_dram_start + dram_found;
    }
    for (i = 0; i < to_add; i++) {
      ctx->found_addrs[ctx->n_found].addr = ctx->backup_addrs[i].addr;
      ctx->found_addrs[ctx->n_found++].pid_idx = ctx->backup_addrs[i].pid_idx;
    }

  } else if ((nvram_found < dram_found) && (ctx->n_switch_backup > 0)) {
    unsigned remaining = dram_found - nvram_found;
    int to_add = min(ctx->n_switch_backup, remaining);
    int i;
    int old_dram_start = nvram_found + 1;
    int new_dram_start = old_dram_start + to_add;
    dram_found = nvram_found + to_add;

    // shift right dram entries
    for (i = dram_found - 1; i >= 0; --i) {
      ctx->found_addrs[new_dram_start + i].addr =
          ctx->found_addrs[old_dram_start + i].addr;
      ctx->found_addrs[new_dram_start + i].pid_idx =
          ctx->found_addrs[old_dram_start + i].pid_idx;
    }

    for (i = 0; i < to_add; ++i) {
      ctx->found_addrs[nvram_found].addr = ctx->switch_backup_addrs[i].addr;
      ctx->found_addrs[nvram_found].pid_idx =
          ctx->switch_backup_addrs[i].pid_idx;
      ++nvram_found;
    }
    ctx->found_addrs[nvram_found].pid_idx = 0;
    ctx->n_found = nvram_found * 2 + 1; // discard last entries
  } else {
    ctx->found_addrs[0].pid_idx = SEPARATOR;
    ctx->n_found = 1;
  }

  return 0;
}

// returns 0 if success, negative value otherwise
int find_candidate_pages(struct pte_callback_context_t *ctx, u32 n_pages,
                         int mode) {
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
}

enum pool_t { DRAM_POOL, NVRAM_POOL };

// page count to KiB
static const int *get_pool_nodes(const enum pool_t pool) {
  switch (pool) {
  case DRAM_POOL:
    return DRAM_NODES;
  case NVRAM_POOL:
    return NVRAM_NODES;
  }

  pr_err("Unknown pool %d\n", pool);
  return ERR_PTR(-EINVAL);
}

static size_t get_pool_size(const enum pool_t pool) {
  switch (pool) {
  case DRAM_POOL:
    return n_dram_nodes;
  case NVRAM_POOL:
    return n_nvram_nodes;
  }

  pr_err("Unknown pool %d\n", pool);
  return 0;
}

static const char *get_pool_name(const enum pool_t pool) {
  switch (pool) {
  case DRAM_POOL:
    return "DRAM";
  case NVRAM_POOL:
    return "NVRAM";
  default:
    return "Unknown";
  }
}

static u32 get_real_memory_usage_per(enum pool_t pool) {
  int i = 0;
  u64 totalram = 0, freeram = 0;
  const int *nodes = get_pool_nodes(pool);
  size_t size = get_pool_size(pool);
  if (IS_ERR(nodes) || size == 0)
    return 0;
  for (i = 0; i < size; ++i) {
    struct sysinfo inf;
    g_si_meminfo_node(&inf, nodes[i]);
    totalram += inf.totalram;
    freeram += inf.freeram;
  }

  // integer division so we need to scale the values so the quotient != 0
  return (K(totalram - freeram) * 100 / K(totalram));
}

// returns used memory for pool in KiB (times the usage factor)
// K(totalram - freeram) / K(totalram) is between [0, 1]
// by multiplying by USAGE_FACTOR we can decrease the ratio above
// e.g. reduced DRAM from 8GiB to 4GiB, returns how many KiB of these 4GiB are being used
static u32 get_memory_usage_percent(enum pool_t pool) {
  int i = 0;
  u64 totalram = 0, freeram = 0;
  const int *nodes = get_pool_nodes(pool);
  size_t size = get_pool_size(pool);
  u32 ratio;
  if (pool == DRAM_POOL) {
    ratio = DRAM_MEM_USAGE_RATIO;
  } else {
    ratio = NVRAM_MEM_USAGE_RATIO;
  }
  if (IS_ERR(nodes) || size == 0)
    return 0;
  for (i = 0; i < size; ++i) {
    struct sysinfo inf;
    g_si_meminfo_node(&inf, nodes[i]);
    totalram += inf.totalram;
    // freeram += inf.freeram;
  }

  mutex_lock(&USAGE_mtx);
  if (pool == DRAM_POOL) {
    freeram = K(totalram) - dram_usage;
  } else {
    freeram = K(totalram) - nvram_usage;
  }
  mutex_unlock(&USAGE_mtx);

  // pr_info("K(totalram) - freeram = %llu", (K(totalram) - freeram));
  // pr_info("((K(totalram) - freeram) * 100 / K(totalram)) = %llu", ((K(totalram) - freeram) * 100 / K(totalram)));

  // integer division so we need to scale the values so the quotient != 0
  return ((K(totalram) - freeram) * 100 / K(totalram)) * 100 / ratio;
}

// number of bytes in total for pool (after being reduced with a certain ratio)
static u64 get_memory_total_ratio(enum pool_t pool) {
  int i = 0;
  u64 totalram = 0;
  const int *nodes = get_pool_nodes(pool);
  const size_t size = get_pool_size(pool);
  u64 ratio;
  if (pool == DRAM_POOL) {
    ratio = DRAM_MEM_USAGE_RATIO;
  } else {
    ratio = NVRAM_MEM_USAGE_RATIO;
  }
  if (IS_ERR(nodes) || size == 0)
    return 0;
  for (i = 0; i < size; ++i) {
    struct sysinfo inf;
    g_si_meminfo_node(&inf, nodes[i]);
    totalram += inf.totalram;
  }

  return totalram * PAGE_SIZE * ratio / 100;
}

static u64 get_memory_total(enum pool_t pool) {
  int i = 0;
  u64 totalram = 0;
  const int *nodes = get_pool_nodes(pool);
  const size_t size = get_pool_size(pool);
  if (IS_ERR(nodes) || size == 0)
    return 0;
  for (i = 0; i < size; ++i) {
    struct sysinfo inf;
    g_si_meminfo_node(&inf, nodes[i]);
    totalram += inf.totalram;
  }

  return totalram * PAGE_SIZE;
}

int g_switch_act = 1;
int g_thresh_act = 1;

static u32 kmod_migrate_pages(struct pte_callback_context_t *, int n_pages,
                              int mode);

// MAIN ENTRY POINT
int ambix_check_memory(void) {
  u32 n_migrated = 0;
  struct pte_callback_context_t *ctx = &g_context;

  pr_debug("Memory migration routine\n");

  mutex_lock(&PIDs_mtx);
  refresh_pids();
  if (PIDs_size == 0) {
    pr_debug("No bound processes...\n");
    goto release_return_acm;
  }

  walk_ranges_usage();
  // pr_info("dram_usage = %llu nvram_usage = %llu", dram_usage, nvram_usage);
  // pr_info("dram_usage_percentage = %u nvram_usage_percentage = %u", get_memory_usage_percent(DRAM_POOL), get_memory_usage_percent(NVRAM_POOL));
  pr_info("Ambix DRAM Usage: %d\n", get_memory_usage_percent(DRAM_POOL));
  pr_info("Ambix NVRAM Usage: %d\n", get_memory_usage_percent(NVRAM_POOL));

  pr_info("System DRAM Usage: %d\n", get_real_memory_usage_per(DRAM_POOL));
  pr_info("System NVRAM Usage: %d\n", get_real_memory_usage_per(NVRAM_POOL));
  if (g_switch_act) {
    u64 pmm_bw = 0;

    if (PMM_MIXED) {
      pmm_bw = perf_counters_pmm_writes() + perf_counters_pmm_reads();
    } else {
      pmm_bw = perf_counters_pmm_writes();
    }

    pr_info("BANDWIDTH PMM = %lld", pmm_bw);
    pr_debug("ppm_bw: %lld, NVRAM_BW_THRESH: %d\n", pmm_bw,
             NVRAM_BANDWIDTH_THRESHOLD);
    if (pmm_bw >= NVRAM_BANDWIDTH_THRESHOLD) {
      u64 tsc_start = tsc_rd(), clear_us, migrate_us;
      clear_nvram_ptes(ctx);
      clear_us = tsc_to_usec(tsc_rd() - tsc_start);

      if (get_memory_usage_percent(DRAM_POOL) < DRAM_MEM_USAGE_TARGET_PERCENT && get_real_memory_usage_per(DRAM_POOL) < AMBIX_DRAM_HARD_LIMIT) {
        u64 n_bytes, n_bytes_sys;
        u32 n_pages, num;

        // [DRAM_USAGE_LIMIT (%) - DRAM_USAGE_NODE (%)] * TOTAL_MEM_NODE
        // (#bytes)
        n_bytes_sys = ((AMBIX_DRAM_HARD_LIMIT - get_real_memory_usage_per(DRAM_POOL)) * get_memory_total(DRAM_POOL)) / 100;
        n_bytes = ((DRAM_MEM_USAGE_LIMIT_PERCENT -
              get_memory_usage_percent(DRAM_POOL)) *
            get_memory_total_ratio(DRAM_POOL)) / 100;

        n_pages = min(n_bytes_sys / PAGE_SIZE, min(n_bytes / PAGE_SIZE, (u64)MAX_N_FIND));

        tsc_start = tsc_rd();
        num = kmod_migrate_pages(ctx, n_pages, NVRAM_INTENSIVE_MODE);
        migrate_us = tsc_to_usec(tsc_rd() - tsc_start);

        n_migrated += num;
        pr_info("NVRAM->DRAM [B]: Migrated %d intensive pages out of %d."
                " (%lldus cleanup; %lldus migration) \n",
                num, n_pages, clear_us, migrate_us);
      } else {
        u32 num;
        tsc_start = tsc_rd();
        num = kmod_migrate_pages(ctx, MAX_N_SWITCH, SWITCH_MODE);
        migrate_us = tsc_to_usec(tsc_rd() - tsc_start);
        n_migrated += num;
        pr_info("DRAM<->NVRAM [B]: Switched %d out of %d pages."
                " (%lldus cleanup; %lldus migration)\n",
                num, 2 * MAX_N_SWITCH, clear_us, migrate_us);
      }
    }
  }
  if (g_thresh_act) {
    pr_debug("Thresholds: DRAM limit %d of %d; NVRAM target %d of %d\n",
             get_memory_usage_percent(DRAM_POOL), DRAM_MEM_USAGE_LIMIT_PERCENT,
             get_memory_usage_percent(NVRAM_POOL),
             NVRAM_MEM_USAGE_TARGET_PERCENT);
    if ((get_memory_usage_percent(DRAM_POOL) > DRAM_MEM_USAGE_LIMIT_PERCENT) &&
        ((get_memory_usage_percent(NVRAM_POOL) <
           NVRAM_MEM_USAGE_TARGET_PERCENT) && get_real_memory_usage_per(NVRAM_POOL) < AMBIX_NVRAM_HARD_LIMIT)) {
      u64 n_bytes_sys = ((AMBIX_NVRAM_HARD_LIMIT - get_real_memory_usage_per(NVRAM_POOL)) * get_memory_total(NVRAM_POOL)) / 100;
      u64 n_bytes = min((get_memory_usage_percent(DRAM_POOL) -
                         DRAM_MEM_USAGE_TARGET_PERCENT) *
                            get_memory_total_ratio(DRAM_POOL),
                        (NVRAM_MEM_USAGE_TARGET_PERCENT -
                         get_memory_usage_percent(NVRAM_POOL)) *
                            get_memory_total_ratio(NVRAM_POOL)) / 100;
      u32 n_pages = min(n_bytes_sys / PAGE_SIZE, min(n_bytes / PAGE_SIZE, (u64)MAX_N_FIND));
      u64 const tsc_start = tsc_rd();
      u32 num = kmod_migrate_pages(ctx, n_pages, DRAM_MODE);
      u64 const migrate_us = tsc_to_usec(tsc_rd() - tsc_start);
      n_migrated += num;
      pr_info("DRAM->NVRAM [U]: Migrated %d out of %d pages."
              " (%lldus)\n",
              num, n_pages, migrate_us);
    } else if (!g_switch_act &&
               (get_memory_usage_percent(NVRAM_POOL) >
                NVRAM_MEM_USAGE_LIMIT_PERCENT) &&
               (get_memory_usage_percent(DRAM_POOL) <
                DRAM_MEM_USAGE_TARGET_PERCENT) && get_real_memory_usage_per(DRAM_POOL) < AMBIX_DRAM_HARD_LIMIT) {
      s64 n_bytes = min((get_memory_usage_percent(NVRAM_POOL) -
                         NVRAM_MEM_USAGE_TARGET_PERCENT) *
                            get_memory_total_ratio(NVRAM_POOL),
                        (DRAM_MEM_USAGE_TARGET_PERCENT -
                         get_memory_usage_percent(DRAM_POOL)) *
                            get_memory_total_ratio(DRAM_POOL)) / 100;
      s64 n_bytes_sys = ((AMBIX_DRAM_HARD_LIMIT - get_real_memory_usage_per(DRAM_POOL)) * get_memory_total(DRAM_POOL)) / 100;
      u32 n_pages = min(n_bytes / PAGE_SIZE, n_bytes_sys / PAGE_SIZE);
      u64 const tsc_start = tsc_rd();
      u32 num = kmod_migrate_pages(ctx, n_pages, NVRAM_MODE);
      u64 const migrate_us = tsc_to_usec(tsc_rd() - tsc_start);
      n_migrated += num;
      pr_info("NVRAM->DRAM [U]: Migrated %d out of %d pages."
              " (%lldus)\n",
              num, n_pages, migrate_us);
    }
  }

release_return_acm:
  mutex_unlock(&PIDs_mtx);
  return n_migrated;
}

static int do_migration(const addr_info_t found_addrs[], size_t n_found,
                        enum pool_t destination);

static int do_switch(const addr_info_t found_addrs[], const size_t n_found) {
  u32 sep;
  for (sep = 0; sep < n_found && found_addrs[sep].pid_idx != SEPARATOR; ++sep)
    ;
  if (sep == n_found) {
    pr_warn("Can't find separator");
    return 0;
  }
  pr_debug("Switching: [0, %d], [%d, %ld]\n", sep, sep + 1, n_found);
  return do_migration(found_addrs + sep + 1, n_found - sep - 1, NVRAM_POOL);
  +do_migration(found_addrs, sep, DRAM_POOL);
}

/**
 * returns number of migrated pages
 */
static u32 kmod_migrate_pages(struct pte_callback_context_t *ctx,
                              const int nr_pages, const int mode) {
  int rc;
  u32 nr;
  u64 tsc_start, find_candidates_us;
  pr_debug("It was requested %d page migrations\n", nr_pages);

  tsc_start = tsc_rd();
  rc = find_candidate_pages(ctx, nr_pages, mode);
  find_candidates_us = tsc_to_usec(tsc_rd() - tsc_start);
  if (rc) {
    pr_debug("No candidates were found (%lldus)\n", find_candidates_us);
    return 0;
  }

  pr_debug("Found %d candidates (%lldus)\n", ctx->n_found, find_candidates_us);

  nr = 0;
  tsc_start = tsc_rd();
  migration_type = mode;
  switch (mode) {
  case DRAM_MODE:
    nr = do_migration(ctx->found_addrs, ctx->n_found, NVRAM_POOL);
    pr_debug("DRAM migration of %d pages took %lldus", nr,
             tsc_to_usec(tsc_rd() - tsc_start));
    break;
  case NVRAM_MODE:
  case NVRAM_WRITE_MODE:
  case NVRAM_INTENSIVE_MODE:
    nr = do_migration(ctx->found_addrs, ctx->n_found, DRAM_POOL);
    pr_debug("NVRAM migration of %d pages took %lldus", nr,
             tsc_to_usec(tsc_rd() - tsc_start));
    break;
  case SWITCH_MODE:
    nr = do_switch(ctx->found_addrs, ctx->n_found);
    pr_debug("Switch of %d pages took %lldus", nr,
             tsc_to_usec(tsc_rd() - tsc_start));
    break;
  }
  return nr;
}

static struct page *alloc_dst_page(struct page *page, unsigned long data) {
  int nid = (int)data;
  struct page *newpage;

  newpage =
      __alloc_pages_node(nid,
                         (GFP_HIGHUSER_MOVABLE | __GFP_THISNODE |
                          __GFP_NOMEMALLOC | __GFP_NORETRY | __GFP_NOWARN) &
                             ~__GFP_RECLAIM,
                         0);

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

static int add_page_for_migration(struct mm_struct *mm, unsigned long addr,
                                  int node, struct list_head *pagelist) {
  struct vm_area_struct *vma;
  struct page *page;
  unsigned int follflags;
  int err;

  mmap_read_lock(mm);
  err = -EFAULT;
  vma = find_vma(mm, addr);
  if (!vma || addr < vma->vm_start || !g_vma_migratable(vma)) {
    pr_debug("Can not find vma.\n");
    goto out;
  }

  /* FOLL_DUMP to ignore special (like zero) pages */
  follflags = FOLL_GET | FOLL_DUMP;
  page = g_follow_page(vma, addr, follflags);

  err = PTR_ERR(page);
  if (IS_ERR(page)) {
    pr_debug("Can not follow page.\n");
    goto out;
  }

  err = -ENOENT;
  if (!page) {
    pr_debug("Page is empty.\n");
    goto out;
  }

  err = 0;
  if (page_to_nid(page) == node) {
    pr_debug("Page is already on desired node.\n");
    goto out_putpage;
  }

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
    if (err) {
      pr_debug("Failed to isolate page.\n");
      goto out_putpage;
    }

    err = 1;
    list_add_tail(&head->lru, pagelist);
    mod_node_page_state(page_pgdat(head),
                        NR_ISOLATED_ANON + page_is_file_lru(head),
                        thp_nr_pages(head));

#ifdef DEBUG_MIGRATIONS
    unsigned long long ts = ktime_get_real_fast_ns();
    pr_info("0x%lx,%d,%d,%d,%llu", addr, page_to_nid(page), node, migration_type, ts);
#endif
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

static int do_migration(const addr_info_t *const found_addrs,
                        const size_t n_found, const enum pool_t dst) {
  LIST_HEAD(pagelist);
  size_t i;
  const int *node_list = get_pool_nodes(dst);
  int node = node_list[0]; // FIXME: we need to pick nodes dynamically, relaying
                           // on space availability
  int err = 0;

  if (node < 0 || node >= MAX_NUMNODES || !node_state(node, N_MEMORY)) {
    pr_err("Invalid node %d", node);
    return 0;
  }

  pr_debug("DO MIGRATION: %ld pages -> %s", n_found, get_pool_name(dst));
  my_lru_cache_disable();
  for (i = 0; i < n_found; ++i) {
    unsigned long addr = (unsigned long)untagged_addr(found_addrs[i].addr);
    size_t idx = found_addrs[i].pid_idx;
    struct task_struct *t = get_pid_task(PIDs[idx].__pid, PIDTYPE_PID);
    if (!t) {
      continue;
    }

    err = add_page_for_migration(t->mm, addr, node, &pagelist);
    put_task_struct(t);
    if (err > 0)
      /*Page is successfully queued for migration*/
      continue;
    break;
  }

  if (list_empty(&pagelist)) {
    pr_debug("Page list is empty!\n");
    err = 0;
    goto out;
  }

  err = g_migrate_pages(&pagelist, alloc_dst_page, NULL, (unsigned long)node,
                        MIGRATE_SYNC, MR_SYSCALL);

  if (err) {
    pr_debug("migrate_pages has returned en error: %d\n", err);
    err = i - err;
    g_putback_movable_pages(&pagelist);
    goto out;
  }

  pr_debug("Successfully migrated %ld\n", i);
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

int ambix_init(void) {
  pr_debug("Initializing\n");

#define M(RET, NAME, SIGNATURE)                                                \
  if (!(g_##NAME = (NAME##_t)the_kallsyms_lookup_name(#NAME))) {               \
    pr_err("Can't lookup '" #NAME "' function.");                              \
    return -1;                                                                 \
  }
#include "IMPORT.M"
#undef M

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 5)
  if (!(g_lru_disable_count =
            (atomic_t *)the_kallsyms_lookup_name("lru_disable_count"))) {
    pr_err("Can't lookup 'lru_disable_count' variable.");
    return -1;
  }
#endif

  {
    size_t i;
    for (i = 0; i < get_pool_size(DRAM_POOL); ++i) {
      int n = get_pool_nodes(DRAM_POOL)[i];
      if (!node_online(n)) {
        pr_err("DRAM node %d is not online.\n", n);
        return -1;
      }
    }
    for (i = 0; i < get_pool_size(NVRAM_POOL); ++i) {
      int n = get_pool_nodes(NVRAM_POOL)[i];
      if (!node_online(n)) {
        pr_err("NVRAM node %d is not online.\n", n);
        return -1;
      }
    }
  }

  return 0;
}

void ambix_cleanup(void) { pr_debug("Cleaning up\n"); }
