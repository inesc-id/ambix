#define pr_fmt(fmt) "test_kmod.main: " fmt

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/nodemask.h>
#include <linux/module.h> /* Needed by all modules */
#include <linux/pid.h>
#include <linux/proc_fs.h>  /* Necessary because we use the proc fs */
#include <linux/seq_file.h> /* for seq_file */
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include "find_kallsyms_lookup_name.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("inesc");
MODULE_DESCRIPTION("Kernel Move Pages Test");
MODULE_VERSION("0.10");

typedef int (*kmove_pages_type)(int, unsigned long, const void**, const int*, int*, int);

kmove_pages_type kernel_move_pages;


typedef int (*do_pages_move_type)(struct mm_struct*, nodemask_t, unsigned long, const void **, const int *, int *, int);

do_pages_move_type do_pages_move;

typedef struct mm_struct* (*find_mm_struct_type)(int, nodemask_t*);

find_mm_struct_type find_mm_struct;

static ssize_t kmod_proc_write(struct file *file, const char __user *buffer,
                               size_t count, loff_t *ppos) {
  char *buf = NULL;
  ssize_t rc = count;
  int page_count, i;

  pr_info("proc_write from %u\n", current->pid);
  buf = memdup_user_nul(buffer, count);
  if (IS_ERR(buf))
    return PTR_ERR(buf);

  buf[count] = '\0';

  page_count = count / 16;

  unsigned long page_addrs[4];
  int nodes[] = {2,2,2,2};
  int status[] = {123, 123, 123, 123};
  int pid;

  sscanf(buf, "%d:%lx:%lx:%lx:%lx:", &pid, &page_addrs[0], &page_addrs[1], &page_addrs[2], &page_addrs[3]);


  struct mm_struct *mm;
  nodemask_t task_nodes;

  mm = find_mm_struct(pid, &task_nodes);
  if (IS_ERR(mm)) {
    printk(KERN_CONT "AQUIIII");  
    return -1;
  }

  rc = do_pages_move(mm, task_nodes, 1, (const void **)&page_addrs,
				    nodes, status, 1 << 2);

    printk(KERN_CONT "rc = %d\n", rc);
    printk(KERN_CONT "status = %d\n", *status);

    // rc = kernel_move_pages(pid, 1, (const void **)b, nodes, status, 1<<2);

out:
  kfree(buf);
  return rc;
}

static int kmod_show(struct seq_file *s, void *private) {
  pr_info("Show\n");
  seq_printf(s, "test_kmod\n");
  return 0;
}

static int kmod_proc_open(struct inode *node, struct file *file) {
  return single_open(file, kmod_show, NULL);
};

static const struct proc_ops kmod_proc_ops = {
    .proc_open = kmod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_write = kmod_proc_write,
    .proc_release = single_release,
};

#define PROC_NAME "test_kmod"
int init_module(void) {
  struct proc_dir_entry *entry;
  int rc;

  pr_info("Initialization\n");

  // TODO kernel_move_pages
  if ((rc = find_kallsyms_lookup_name())) {
    pr_warn("Can't lookup 'kallsyms_lookup_name'");
    return rc;
  }

  pr_info("kernel_move_pages = 0x%lx\n",
          the_kallsyms_lookup_name("kernel_move_pages"));

  kernel_move_pages = the_kallsyms_lookup_name("kernel_move_pages");
  do_pages_move = the_kallsyms_lookup_name("do_move_pages");
  find_mm_struct = the_kallsyms_lookup_name("find_mm_struct");

  pr_info("our kernel_move_pages = 0x%lx\n", kernel_move_pages);

  entry = proc_create(PROC_NAME, 0666, NULL, &kmod_proc_ops);
  if (!entry) {
    pr_warn("proc initialization failed");
    return -ENOMEM;
  }

  return 0;
}

void cleanup_module(void) {
  pr_info("release\n");
  remove_proc_entry(PROC_NAME, NULL);
}
