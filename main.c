#define pr_fmt(fmt) "ambix.main: " fmt
/**
 * @file    main.c
 * @author  INESC-ID
 * @date    26 jul 2023
 * @version 2.2.0
 * @brief  Kernel module init, cleanup and procfs handling routines. Intended
 * for the 5.10.0 linux kernel. Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/mm.h>
#include <linux/module.h> /* Needed by all modules */
#include <linux/pid.h>
#include <linux/proc_fs.h> /* Necessary because we use the proc fs */
#include <linux/seq_file.h> /* for seq_file */
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#include "config.h"
#include "find_kallsyms_lookup_name.h"
#include "perf_counters.h"
#include "placement.h"
#include "tsc.h"
#include "vm_management.h"
#include "sys_mem_info.h"

#define PROC_NAME "objects"
#define PROC_DIR_NAME "ambix"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("INESC-ID");
MODULE_DESCRIPTION("Ambix - Bandwidth-aware page replacement");
MODULE_VERSION("2.2.0");

//static bool g_show_aggregates = true;
static bool g_perf_enabled = true;

/**
 * Handler to generate output when reading from /proc/ambix
 *
 */
static int kmod_show(struct seq_file *s, void *private)
{
	seq_printf(
		s,
		"fast_tier_usage, slow_tier_usage, allocation_site\n%llu, %llu, -1\n",
		get_memory_usage_bytes(DRAM_POOL),
		get_memory_usage_bytes(NVRAM_POOL));

	return 0;
}

/**
 * Write handler, responsible for parsing commands and calling the appropriate
 * function
 *
 */
static ssize_t kmod_proc_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *ppos)
{
	char *buf = NULL;
	ssize_t rc = count;
	unsigned long long ts = ktime_get_real_fast_ns();

	pr_info("proc_write from %u @ %llu", current->pid, ts);
	buf = memdup_user_nul(buffer, count);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	/* work around \n when echo'ing into proc */
	if (buf[count - 1] == '\n')
		buf[count - 1] = '\0';

	if (!strncmp(buf, "bind_range ", 11)) {
		unsigned long start, end, allocation_site, size;
		int retval = sscanf(buf, "bind_range %lx %lx %lx %lx", &start,
				    &end, &allocation_site, &size);
		pr_info("retval = %d start = %li end = %li", retval,
			*(long *)&start, *(long *)&end);
		if (retval != 4) {
			pr_crit("Couldn't parse bind_range arguments pid=%d start=%lu "
				"end=%lu",
				current->pid, start, end);
			rc = -EINVAL;
		} else if (ambix_bind_pid_constrained(current->pid, start, end,
						      allocation_site, size,
						      1)) {
			pr_crit("Couldn't bind in bind_range");
			rc = -EINVAL;
		}
		pr_info("bind,%d,%llu", current->pid, ts);
	} else if (!strncmp(buf, "bind_range_monitoring", 21)) {
		unsigned long start, end, allocation_site, size;
		int retval =
			sscanf(buf, "bind_range_monitoring %lx %lx %lx %lx",
			       &start, &end, &allocation_site, &size);
		pr_info("retval = %d start = %li end = %li", retval,
			*(long *)&start, *(long *)&end);
		if (retval != 4) {
			pr_crit("Couldn't parse bind_range arguments pid=%d start=%lu "
				"end=%lu",
				current->pid, start, end);
			rc = -EINVAL;
		} else if (ambix_bind_pid_constrained(current->pid, start, end,
						      allocation_site, size,
						      0)) {
			pr_crit("Couldn't bind in bind_range");
			rc = -EINVAL;
		}
		pr_info("bind_monitor_only,%d,%llu", current->pid, ts);

	} else if (!strncmp(buf, "bind_range_monitoring_pid", 25)) {
		int pid, retval;
		unsigned long start, end, allocation_site, size;
		retval = sscanf(buf,
				"bind_range_monitoring_pid %d %lx %lx %lx %lx",
				&pid, &start, &end, &allocation_site, &size);
		pr_info("retval = %d start = %li end = %li", retval,
			*(long *)&start, *(long *)&end);
		if (retval != 4) {
			pr_crit("Couldn't parse bind_range arguments pid=%d start=%lu "
				"end=%lu",
				current->pid, start, end);
			rc = -EINVAL;
		} else if (ambix_bind_pid_constrained(
				   pid, start, end, allocation_site, size, 0)) {
			pr_crit("Couldn't bind in bind_range");
			rc = -EINVAL;
		}
		pr_info("bind_monitor_only,%d,%llu", current->pid, ts);

	} else if (!strncmp(buf, "bind_range_pid", 14)) {
		int pid, retval;
		unsigned long start, end, allocation_site, size;
		retval = sscanf(buf, "bind_range_pid %d %lx %lx %lx %lx", &pid,
				&start, &end, &allocation_site, &size);
		pr_debug("retval = %d pid = %d start = %li end = %li", retval,
			 pid, *(long *)&start, *(long *)&end);
		if (retval != 5) {
			pr_crit("Couldn't parse bind_range_pid arguments pid=%d start=%lu "
				"end=%lu",
				pid, start, end);
			rc = -EINVAL;
		} else if (ambix_bind_pid_constrained(
				   pid, start, end, allocation_site, size, 1)) {
			pr_crit("Couldn't bind in bind_range_pid");
			rc = -EINVAL;
		}
		pr_info("bind,%d,%llu", current->pid, ts);
	} else if (!strcmp(buf, "bind")) {
		if (ambix_bind_pid(current->pid)) {
			rc = -EINVAL;
		}
		pr_info("bind,%d,%llu", current->pid, ts);
	} else if (!strcmp(buf, "unbind")) {
		if (ambix_unbind_pid(current->pid)) {
			rc = -EINVAL;
		}
		pr_info("unbind,%d,%llu", current->pid, ts);
	} else if (!strcmp(buf, "bind_monitoring")) {
		if (ambix_bind_pid_constrained(current->pid, 0, 0, 0, 0, 0)) {
			rc = -EINVAL;
		}
		pr_info("bind,%d,%llu", current->pid, ts);
	} else if (!strcmp(buf, "unbind_monitoring")) {
		if (ambix_unbind_range_pid(current->pid, 0, 0)) {
			rc = -EINVAL;
		}
		pr_info("unbind,%d,%llu", current->pid, ts);
	}  else if (!strncmp(buf, "unbind_range_monitoring", 23)) {
		unsigned long start, end;
		int retval;
		retval = sscanf(buf, "unbind_range_monitoring %lx %lx", &start,
				&end);
		if (retval != 2) {
			pr_crit("Couldn't unbind in unbind_range");
		}
		if (ambix_unbind_range_pid(current->pid, start, end)) {
			rc = -EINVAL;
		}
		pr_info("unbind,%d,%llu", current->pid, ts);
	} else if (!strncmp(buf, "unbind_range_monitoring_pid", 27)) {
		unsigned long start, end;
		int retval, pid;
		retval = sscanf(buf, "unbind_range_monitoring_pid %d %lx %lx",
				&pid, &start, &end);
		if (retval != 3) {
			pr_crit("Couldn't unbind in unbind_range");
		}
		if (ambix_unbind_range_pid(pid, start, end)) {
			rc = -EINVAL;
		}
		pr_info("unbind,%d,%llu", pid, ts);

	} else if (!strncmp(buf, "unbind_range_pid", 12)) {
		int pid, retval;
		unsigned long start, end;
		retval = sscanf(buf, "unbind_range_pid %d %lx %lx", &pid,
				&start, &end);
		if (retval != 3) {
			pr_crit("Couldn't unbind in unbind_range_pid");
		}
		if (ambix_unbind_range_pid(pid, start, end)) {
			rc = -EINVAL;
		}
		pr_info("unbind,%d,%llu", current->pid, ts);
	} else if (!strncmp(buf, "bind_pid", 8)) {
		pid_t pid;
		int retval;
		retval = sscanf(buf, "bind_pid %d", &pid);
		if (retval != 1) {
			pr_warn("Can't parse pid '%s'", buf + 9);
			rc = -EINVAL;
		} else if (ambix_bind_pid(pid)) {
			rc = -EINVAL;
		}
	} else if (!strncmp(buf, "unbind_pid", 10)) {
		pid_t pid;
		int retval;
		retval = sscanf(buf, "unbind_pid %d", &pid);
		if (retval != 1) {
			pr_warn("Can't parse pid '%s'", buf + 11);
			rc = -EINVAL;
		} else if (ambix_unbind_pid(pid)) {
			rc = -EINVAL;
		}
		pr_info("unbind,%d,%llu", current->pid, ts);
	} else if (!strcmp(buf, "enable")) {
		perf_counters_enable();
	} else if (!strcmp(buf, "disable")) {
		perf_counters_disable();
	} else {
		pr_info("unknown cmd %s\n", buf);
		rc = -EINVAL;
	}
	kfree(buf);
	return rc;
}

/**
 * Open Handler, call single_open (<linux/seq_file.h>)
 *
 */
static int kmod_proc_open(struct inode *node, struct file *file)
{
	return single_open(file, kmod_show, NULL);
}

static const struct proc_ops kmod_proc_ops = {
	.proc_open = kmod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_write = kmod_proc_write,
	.proc_release = single_release,
};

// ---------------------------------------------------------------------------------

static bool g_work_queue_die = false;
static unsigned g_time_interval = 1000;

static void work_queue_routine(struct work_struct *dummy);
static DECLARE_DELAYED_WORK(g_task, work_queue_routine);

/**
 * Call the main Ambix function every g_time_interval ms
 *
 */
static void work_queue_routine(struct work_struct *dummy)
{
	ambix_check_memory();
	if (!g_work_queue_die) {
		schedule_delayed_work(&g_task,
				      msecs_to_jiffies(g_time_interval));
	}
}

/**
 * Initialize the job queue
 *
 */
int work_queue_init(void)
{
	pr_debug("Initializing work queue");
	work_queue_routine(NULL);
	return 0;
}

/**
 * Cleanup the job queue
 *
 */
void work_queue_cleanup(void)
{
	pr_debug("Deinitializing work queue");
	g_work_queue_die = true;
	cancel_delayed_work_sync(&g_task);
}

// ---------------------------------------------------------------------------------

/**
 * Initializes the kernel module
 *
 * Looks up non exported kernel symbols from /proc/kallsyms
 * Initializes perf counters for DRAM and NVRAM
 * Creates an entry in procfs (at /proc/ambix)
 * Calls ambix_init, responsible for the initialization of the necessary data
 * structures
 *
 */
int init(void)
{
	struct proc_dir_entry *entry;
	int rc;

	pr_info("Initialization\n");
	pr_info("DRAM_MEM_USAGE_RATIO = %d\n", DRAM_MEM_USAGE_RATIO);

	tsc_init();

	if ((rc = find_kallsyms_lookup_name())) {
		pr_warn("Can't lookup 'kallsyms_lookup_name'");
		return rc;
	}

	pr_info("walk_page_range address = 0x%lx\n",
		the_kallsyms_lookup_name("walk_page_range"));

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

	proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
	if (!proc_dir) {
		pr_warn("proc initialization failed");
	}

	entry = proc_create(PROC_NAME, 0666, proc_dir, &kmod_proc_ops);
	if (!entry) {
		pr_warn("proc initialization failed");
	}

	if ((rc = work_queue_init())) {
		return rc;
	}

	return 0;
}

/**
 * Cleanup the kernel module
 *
 * Responsible for freeing all the resources acquired in init_module.
 *
 */
void cleanup(void)
{
	struct vm_area_t *current_vm, *tmp;

	pr_info("release\n");
	work_queue_cleanup();
	remove_proc_entry(PROC_NAME, proc_dir);
	write_lock(&my_rwlock);

	list_for_each_entry_safe (current_vm, tmp, &AMBIX_VM_AREAS, node) {
		if (!current_vm->migrate_pages) {
			char filename[128];
			snprintf(filename, 128, "%d.%lu",
				 pid_nr(current_vm->__pid),
				 current_vm->start_addr);
			remove_proc_entry(filename, proc_dir);
		}

		put_pid(current_vm->__pid);
		list_del(&current_vm->node);
		kfree(current_vm);
	}

	write_unlock(&my_rwlock);

	remove_proc_entry(PROC_DIR_NAME, NULL);

	ambix_cleanup();
	perf_counters_disable();
	perf_counters_cleanup();
}

module_init(init);
module_exit(cleanup);
