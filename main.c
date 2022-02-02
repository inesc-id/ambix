#define pr_fmt(fmt) "kmod.main: " fmt

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>   /* Needed for KERN_INFO */
//#include <linux/kstrtox.h>
#include <linux/mm.h>
#include <linux/module.h>   /* Needed by all modules */
#include <linux/pid.h>
#include <linux/proc_fs.h>  /* Necessary because we use the proc fs */
#include <linux/seq_file.h> /* for seq_file */
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#include "find_kallsyms_lookup_name.h"
#include "perf_counters.h"
#include "placement.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilia Kuzmin");
MODULE_DESCRIPTION("Bandwidth-aware page replacement; Ambix successor");
MODULE_VERSION("0.10");

static bool g_show_aggregates = true;
static bool g_perf_enabled = true;

/**
 * This function is called for each "step" of a sequence
 *
 */
static int kmod_show(struct seq_file *s, void * private)
{
    //pr_debug("Show\n");
    if (g_show_aggregates) {
        const u64
            pmm_reads = perf_counters_pmm_reads(),
            pmm_writes = perf_counters_pmm_writes(),
            ddr_reads = perf_counters_ddr_reads(),
            ddr_writes = perf_counters_ddr_writes();
        seq_printf(s,
                "PMM READS: %lld Mb/s\n"
                "PMM WRITES: %lld Mb/s\n"
                "DDR READS: %lld Mb/s\n"
                "DDR WRITES: %lld Mb/s\n"
                "PMM BW: %lld Mb/s\n"
                "DDR BW: %lld Mb/s\n" ,
                    pmm_reads,
                    pmm_writes,
                    ddr_reads,
                    ddr_writes,
                    pmm_reads + pmm_writes,
                    ddr_reads + ddr_writes);
    }
    else {
        size_t i;
        for (i = 0; i < EVENTs_size; ++i) {
            u64 value, time;
            bool enabled = perf_counters_read_change(i, &value, &time);
            struct counter_t * const info = perf_counters_info(i);
            seq_printf(s, "%ld:%s e:%s; dv:%lld %s; dt:%lld;\n",
                    i, info->name,
                    enabled ? "T" : "F",
                    value / jiffies_to_sec(time) * info->mult / info->fact,
                    info->unit,
                    jiffies_to_sec(time));
        }
    }
    return 0;
}

static ssize_t kmod_proc_write(
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
    //pr_info("proc_write\n");
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
        if (ambix_bind_pid(current->pid)) {
            rc = -EINVAL;
        }
    }
    else if (!strcmp(buf, "unbind")) {
        if (ambix_unbind_pid(current->pid)) {
            rc = -EINVAL;
        }
    }
    else if (!strncmp(buf, "bind ", 5)) {
        pid_t pid;
        if (kstrtoint(buf + 5, 10, &pid)) {
            pr_warn("Can't parse pid '%s'", buf + 5);
            rc = -EINVAL;
        }
        else if (ambix_bind_pid(pid)) {
            rc = -EINVAL;
        }
    }
    else if (!strncmp(buf, "unbind ", 7)) {
        pid_t pid;
        if (kstrtoint(buf + 7, 10, &pid)) {
            pr_warn("Can't parse pid '%s'", buf + 7);
            rc = -EINVAL;
        }
        else if (ambix_unbind_pid(pid)) {
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

static int kmod_proc_open(struct inode * node, struct file *file)
{
    return single_open(file, kmod_show, NULL);
};

static const struct proc_ops kmod_proc_ops = {
    .proc_open    = kmod_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_write   = kmod_proc_write,
    .proc_release = single_release,
};

// ---------------------------------------------------------------------------------

static bool g_work_queue_die = false;
static unsigned g_time_interval = 1000;

static void work_queue_routine(struct work_struct *dummy);
static DECLARE_DELAYED_WORK(g_task, work_queue_routine);
static void work_queue_routine(struct work_struct *dummy)
{
    ambix_check_memory();
    if (!g_work_queue_die) {
		schedule_delayed_work(&g_task, msecs_to_jiffies(g_time_interval));
    }
}

int work_queue_init(void)
{
    pr_debug("Initializing work queue");
    //g_workqueue = create_workqueue(WORK_QUEUE_NAME);
    work_queue_routine(NULL);
    return 0;
}

void work_queue_cleanup(void)
{
    pr_debug("Deinitializing work queue");
    g_work_queue_die = true;
    cancel_delayed_work_sync(&g_task);
    //destroy_workqueue(g_workqueue);
}

// ---------------------------------------------------------------------------------

#define PROC_NAME "kmod"
int init_module(void)
{
    struct proc_dir_entry * entry;
    int rc;

    pr_info("Initialization\n");

    if ((rc = find_kallsyms_lookup_name())) {
        pr_warn("Can't lookup 'kallsyms_lookup_name'");
        return rc;
    }

    //pr_info("walk_page_range address = 0x%lx\n", the_kallsyms_lookup_name("walk_page_range"));

    if ((rc = perf_counters_init())) {
        pr_warn("PCM initialization failed");
        return rc;
    }

    if (g_perf_enabled) {
        perf_counters_enable();
    }

    if ((rc = ambix_init())) {
        pr_warn("Ambix initialization failed");
        perf_counters_disable();
        perf_counters_cleanup();
        return rc;
    }

    entry = proc_create(PROC_NAME, 0666, NULL, &kmod_proc_ops);
    if (!entry) {
        pr_warn("proc initialization failed");
        return -ENOMEM;
    }

    if ((rc = work_queue_init())) {
        return rc;
    }

    return 0;
}

void cleanup_module(void)
{
    pr_info("release\n");
	work_queue_cleanup();
    remove_proc_entry(PROC_NAME, NULL);
    ambix_cleanup();
    perf_counters_disable();
    perf_counters_cleanup();
}

