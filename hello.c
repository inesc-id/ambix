#define pr_fmt(fmt) "hello: " fmt

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <linux/kstrtox.h>
#include <linux/mm.h>
#include <linux/module.h>   /* Needed by all modules */
#include <linux/pid.h>
#include <linux/proc_fs.h>  /* Necessary because we use the proc fs */
#include <linux/seq_file.h> /* for seq_file */
#include <linux/slab.h>

#include "find_kallsyms_lookup_name.h"
#include "perf_counters.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilia Kuzmin");
MODULE_DESCRIPTION("Bandwidth-aware page replacement");
MODULE_VERSION("0.01");

/**
 * This function is called for each "step" of a sequence
 *
 */
static int hello_show(struct seq_file *s, void *)
{
    size_t i;

    pr_info("seq_show\n");

    for (i = 0; i < EVENTs_size; ++i) {
        u64 value, time;
        bool enabled = perf_counters_read_change(i, &value, &time);
        seq_printf(s, "%ld: enabled:%s; dv:%lld; dt:%lld;\n", i,
                 enabled ? "T" : "F",
                 value * 64 / 1024 / 1024, time);
    }

    return 0;
}

static int hello_bind(const pid_t pid) {
    pr_info("Binding %d\n", pid);
    return 0;
}

static int hello_unbind(const pid_t pid) {
    pr_info("Un-Binding %d\n", pid);
    return 0;
}

static ssize_t hello_proc_write(
        struct file * file,
        const char __user * buffer,
        size_t count,
        loff_t * ppos)
{
    char * buf = NULL;
    ssize_t rc = count;

//    if (count > LED_MAX_LENGTH)
//        count = LED_MAX_LENGTH;
//
    pr_info("proc_write\n");
    buf = memdup_user_nul(buffer, count);
    if (IS_ERR(buf))
        return PTR_ERR(buf);

    /* work around \n when echo'ing into proc */
    if (buf[count - 1] == '\n')
        buf[count - 1] = '\0';

    ///* before we change anything we want to stop any running timers,
    // * otherwise calls such as on will have no persistent effect
    // */
    //del_timer_sync(&led_blink_timer);

    if (!strcmp(buf, "bind")) {
        if (hello_bind(current->pid)) {
            rc = -EINVAL;
        }
    }
    else if (!strcmp(buf, "unbind")) {
        if (hello_unbind(current->pid)) {
            rc = -EINVAL;
        }
    }
    else if (!strncmp(buf, "bind ", 5)) {
        pid_t pid;
        if (kstrtoint(buf + 5, 10, &pid)) {
            pr_warn("Can't parse pid '%s'", buf + 5);
            rc = -EINVAL;
        }
        else if (hello_bind(pid)) {
            rc = -EINVAL;
        }
    }
    else if (!strncmp(buf, "unbind ", 7)) {
        pid_t pid;
        if (kstrtoint(buf + 7, 10, &pid)) {
            pr_warn("Can't parse pid '%s'", buf + 7);
            rc = -EINVAL;
        }
        else if (hello_unbind(pid)) {
            rc = -EINVAL;
        }
    }
    else if (!strcmp(buf, "enable")) {
        perf_counters_enable();
    }
    else {
        pr_info("unknown cmd %s\n", buf);
        rc = -EINVAL;
    }
    kfree(buf);
    return rc;
}

static int hello_proc_open(struct inode *, struct file *file)
{
    return single_open(file, hello_show, NULL);
};

static const struct proc_ops hello_proc_ops = {
    .proc_open    = hello_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_write   = hello_proc_write,
    .proc_release = single_release,
};


#define PROC_NAME "hello"
int init_module(void)
{
    struct proc_dir_entry * entry;
    int rc;

    pr_info("Initialization");

    if ((rc = find_kallsyms_lookup_name())) {
        pr_info("Can't lookup 'kallsyms_lookup_name'");
        return rc;
    }

    pr_info("walk_page_range address = 0x%lx\n", the_kallsyms_lookup_name("walk_page_range"));

    //test = kallsyms_lookup_name("walk_page_range");
    //remap_pfn_range
    //printk(KERN_INFO "initialization %ld; %p\n", test, &proc_create);
    if ((rc = perf_counters_init())) {
        pr_info("PCM initialization failed");
        return rc;
    }

    entry = proc_create(PROC_NAME, 0666, NULL, &hello_proc_ops);
    if (!entry) {
        pr_info("proc initialization failed");
        return -ENOMEM;
    }

    return 0;
}

void cleanup_module(void)
{
    pr_info("release\n");
    remove_proc_entry(PROC_NAME, NULL);
    perf_counters_disable();
    perf_counters_cleanup();
}

