#define pr_fmt(fmt) "hello: " fmt

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <linux/kstrtox.h>
#include <linux/mm.h>
#include <linux/module.h>   /* Needed by all modules */
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>  /* Necessary because we use the proc fs */
#include <linux/seq_file.h> /* for seq_file */
#include <linux/slab.h>

#include <asm-generic/bug.h>

//#include "perf_counters.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilia Kuzmin");
MODULE_DESCRIPTION("Bandwidth-aware page replacement");
MODULE_VERSION("0.01");

// ------------------------------------------------------------------------------

static u32 CPUs[] = {0}; //0, 16
static size_t CPUs_size = sizeof(CPUs) / sizeof(CPUs[0]);

static u32 IMCs[] = {10}; // {13,14,15,16,17,18}
static size_t IMCs_size = sizeof(IMCs) / sizeof(IMCs[0]);

#define IMC_PPM_READ   0x1 //0xe3
#define IMC_PPM_WRITE  0x2 //0xe7
#define IMC_DDR_READ   0x1// 0x104
#define IMC_DDR_WRITE  0x2// 0x??

// static DEFINE_PER_CPU(struct perf_event *, ppm_bandwidth_read);
// static DEFINE_PER_CPU(struct perf_event *, ppm_bandwidth_write);

// pid == -1 and cpu >= 0
// This  measures all processes/threads on the specified CPU.  This requires
// CAP_PERFMON  (since  Linux  5.8)  or  CAP_SYS_ADMIN   capability   or   a
// /proc/sys/kernel/perf_event_paranoid value of less than 1.

static u64 COUNTERs[] = {
//    IMC_PPM_READ,
//    IMC_PPM_WRITE,
    IMC_DDR_READ,
    IMC_DDR_WRITE,
};
static size_t COUNTERs_size = sizeof(COUNTERs) / sizeof(COUNTERs[0]);
//
struct perf_event ** EVENTs = NULL;
size_t EVENTs_size = 0;// sizeof(EVENTs) / sizeof(EVENTs[0]);

u64 * EVENTs_value = NULL;
unsigned long * EVENTs_time = NULL;


int perf_counters_init(void)
{
    struct perf_event_attr event_attr = {0};
    size_t ev_i = 0;
    size_t i;
    int rc = 0;

    event_attr.size = sizeof(struct perf_event_attr);
    event_attr.disabled = 1;
    event_attr.sample_type = PERF_SAMPLE_IDENTIFIER;
    event_attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    event_attr.inherit = 1;
    event_attr.aux_output = 0;

    EVENTs_size = COUNTERs_size * IMCs_size * CPUs_size;
    EVENTs = kmalloc(sizeof(EVENTs[0]) * EVENTs_size, GFP_KERNEL);
    EVENTs_value = kmalloc(sizeof(EVENTs_value[0]) * EVENTs_size, GFP_KERNEL);
    EVENTs_time = kmalloc(sizeof(EVENTs_time[0]) * EVENTs_size, GFP_KERNEL);

    for (i = 0; i < IMCs_size; ++i) {
        size_t ci;
        event_attr.type = IMCs[i];
        for (ci = 0; ci < COUNTERs_size; ++ci) {
            size_t cpu_i;
            for (cpu_i = 0; cpu_i < CPUs_size; ++cpu_i) {
                struct perf_event * evt;
                unsigned cpu = CPUs[cpu_i];
                event_attr.config = COUNTERs[ci];

                evt = perf_event_create_kernel_counter(&event_attr, cpu,
                            NULL, NULL, NULL);

                if (IS_ERR(evt)) {
                    rc = PTR_ERR(evt);
                    pr_err("Perf event create on CPU %d failed with %d\n", cpu, rc);
                    goto cleanup;
                }

                if (ev_i == EVENTs_size) {
                    pr_err("Creating more events than allocated buffer");
                    rc = -ENOMEM;
                    goto cleanup;
                }

                EVENTs[ev_i++] = evt;
            }
        }
    }

    //event_attr->sample_period = hw_nmi_get_sample_period(watchdog_thresh);

    /* Try to register using hardware perf events */
    //evt = perf_event_create_kernel_counter(&event_attr, cpu, NULL, NULL, NULL);

//                           watchdog_overflow_callback, NULL);
    //this_cpu_write(watchdog_ev, evt);

    return 0;

cleanup:
    for (i = 0; i < ev_i; ++i) {
        perf_event_release_kernel(EVENTs[i]);
        EVENTs[i] = NULL;
    }
    kfree(EVENTs);
    kfree(EVENTs_value);
    kfree(EVENTs_time);
    return rc;
}

void perf_counters_cleanup(void)
{
    size_t i;
    for (i = 0; i < EVENTs_size; ++i) {
        perf_event_release_kernel(EVENTs[i]);
        EVENTs[i] = NULL;
    }
    EVENTs_size = 0;
    kfree(EVENTs);
    kfree(EVENTs_value);
    kfree(EVENTs_time);

    pr_debug("PCM cleaned up");
}

void perf_counters_enable(void)
{
    size_t i;
    for (i = 0; i < EVENTs_size; ++i) {
        u64 enabled, running;
        perf_event_enable(EVENTs[i]);
        EVENTs_time[i] = jiffies;
        EVENTs_value[i] =
             perf_event_read_value(EVENTs[i], &enabled, &running);

        if (!enabled || !running) {
            pr_warn("Failed enable counter %ld", i);
        }
    }
    pr_debug("PCM enabled");
}

bool perf_counters_read_change(const size_t idx, u64 * value, u64 * time)
{
    u64 new_value, enabled, running;
    if (unlikely(idx >= EVENTs_size)) {
        pr_debug("Out of range counter %ld", idx);
        return false;
    }
    new_value = perf_event_read_value(EVENTs[idx], &enabled, &running);
    *value = new_value - EVENTs_value[idx];
    EVENTs_value[idx] = new_value;
    *time = (jiffies - EVENTs_time[idx] + HZ / 2) / HZ;
    EVENTs_time[idx] = jiffies;

    return enabled & running;
}

void perf_counters_disable(void)
{
    size_t i;
    for (i = 0; i < EVENTs_size; ++i) {
        perf_event_disable(EVENTs[i]);
    }
    pr_debug("PCM disabled");
}

// ------------------------------------------------------------------------------


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

