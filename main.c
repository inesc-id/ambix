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

typedef int (*cmd_handler_t)(const char *buf, size_t count);

struct cmd {
	const char *cmd;
	cmd_handler_t handler;
};

//static bool g_show_aggregates = true;
static bool g_perf_enabled = true;
static bool g_work_queue_die = false;
static unsigned g_time_interval = 1000;

static void work_queue_routine(struct work_struct *dummy);
static DECLARE_DELAYED_WORK(g_task, work_queue_routine);

/* Handler to generate output when reading from /proc/ambix/objects */

static int kmod_show(struct seq_file *s, void *private)
{
	struct bound_program_t *entry;

	unsigned long long fast_tier_bytes = 0;
	unsigned long long slow_tier_bytes = 0;

	unsigned long long backup_fast_tier_bytes = 0;
	unsigned long long backup_slow_tier_bytes = 0;

	mutex_lock(&bound_list_mutex);

	list_for_each_entry (entry, &bound_program_list, node) {
		if (pid_nr(entry->__pid) == current->pid) {
			fast_tier_bytes = entry->fast_tier_bytes;
			slow_tier_bytes = entry->slow_tier_bytes;
		}
		backup_fast_tier_bytes += entry->fast_tier_bytes;
		backup_slow_tier_bytes += entry->slow_tier_bytes;
	}

	if(!fast_tier_bytes && !slow_tier_bytes){
		fast_tier_bytes = backup_fast_tier_bytes;
		slow_tier_bytes = backup_slow_tier_bytes;
	}

	mutex_unlock(&bound_list_mutex);

	seq_printf(
		s,
		"fast_tier_usage, slow_tier_usage, allocation_site\n%llu, %llu, -1\n",
		fast_tier_bytes, slow_tier_bytes);

	return 0;
}

static int handle_enable(const char *buf, size_t count)
{
	//TODO: Implement

	return 0;
}

static int handle_disable(const char *buf, size_t count)
{
	//TODO: Implement

	return 0;
}

static int handle_bind(const char *buf, size_t count)
{
	pid_t pid= 0;
	int retval, migrations_enabled;

	retval = sscanf(buf, "bind %d %d", &pid, &migrations_enabled);
	if (retval != 2) {
		pr_warn("Couldn't parse bind arguments pid=%d migrations_enabled=%d", pid, migrations_enabled);
		return -EINVAL;
	}

	pid = pid ? pid : current->pid;

	if (!create_pid_entry(pid, migrations_enabled)) {
		return -EINVAL;
	}

	return 0;
}

static int handle_unbind(const char *buf, size_t count)
{
	pid_t pid = 0;
	int retval;

	retval = sscanf(buf, "unbind %d", &pid);
	if (retval != 1) {
		pr_warn("Couldn't parse unbind arguments pid=%d", pid);
		return -EINVAL;
	}

	pid = pid ? pid : current->pid;

	remove_pid_entry(pid);

	return 0;
}

static int handle_unbind_range_monitoring(const char *buf, size_t count)
{
	unsigned long start, end;
	int retval, pid = 0;

	retval = sscanf(buf, "unbind_range_monitoring %d %lx %lx", &pid,
			&start, &end);

	if (retval != 3) {
		pr_warn("Couldn't parse unbind_range_monitoring arguments pid=%d start=%lu end = %lu",
			pid, start, end);
		return -EINVAL;
	}

	pid = pid ? pid : current->pid;

	remove_memory_range(pid, start, end);

	pr_info("Successfully unbound range_monitoring pid=%d start=%lu end=%lu",
		pid, start, end);

	return 0;
}

static int handle_bind_range_monitoring(const char *buf, size_t count)
{
	unsigned long start, end, allocation_site, size;
	int retval, pid = 0;

	retval = sscanf(buf, "bind_range_monitoring %d %lx %lx %lx %lx", &pid,
			&start, &end, &allocation_site, &size);

	if (retval != 5) {
		pr_warn("Couldn't parse bind_range_monitoring arguments pid=%d start=%lu end = %lu allocation_site = %lu size = %lu ",
			pid, start, end, allocation_site, size);
		return -EINVAL;
	}
	pid = pid ? pid : current->pid;

	if (!add_memory_range(pid, start, end, allocation_site, size)) {
		pr_warn("Couldn't handle bind_range_monitoring request");
		return -EINVAL;
	}

	pr_info("Successfully bound range_monitoring pid=%d start=%lu "
		"end=%lu allocation_site=%lu size=%lu",
		pid, start, end, allocation_site, size);

	return 0;
}

static struct cmd commands[] = {
	{ "bind ", handle_bind },
	{ "unbind ", handle_unbind },
	{ "bind_range_monitoring ", handle_bind_range_monitoring },
	{ "unbind_range_monitoring ", handle_unbind_range_monitoring },
	{ "enable ", handle_enable },
	{ "disable ", handle_disable },
	{ NULL, NULL } // Terminator
};

static ssize_t kmod_proc_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *ppos)
{
	char *buf;
	ssize_t rc = count;
	int ret, i;

	buf = memdup_user_nul(buffer, count);
	if (IS_ERR(buf)) {
		return PTR_ERR(buf);
	}

	/* work around \n when echo'ing into proc */
	if (buf[count - 1] == '\n')
		buf[count - 1] = '\0';

	for (i = 0; commands[i].cmd != NULL; ++i) {
		if (!strncmp(buf, commands[i].cmd, strlen(commands[i].cmd))) {
			ret = commands[i].handler(buf, count);
			if (ret < 0)
				rc = ret;
			goto out;
		}
	}

	pr_info("unknown command: %s\n", buf);
	rc = -EINVAL;

out:
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

/**
 * Call the main Ambix function every g_time_interval ms
 *
 */
static void work_queue_routine(struct work_struct *dummy)
{
	ambix_check_memory();
	if (!g_work_queue_die) {
		queue_delayed_work(system_unbound_wq, &g_task,
				   msecs_to_jiffies(g_time_interval));
		/*schedule_delayed_work(&g_task,
				      msecs_to_jiffies(g_time_interval));*/
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
	pr_info("release\n");
	work_queue_cleanup();
	remove_proc_entry(PROC_NAME, proc_dir);

	struct bound_program_t *pid_entry, *tmp_pid_entry;
	struct memory_range_t *range, *tmp_range;

	mutex_lock(&bound_list_mutex);

	list_for_each_entry_safe (pid_entry, tmp_pid_entry, &bound_program_list,
				  node) {
		mutex_lock(&pid_entry->range_mutex);

		list_for_each_entry_safe (range, tmp_range,
					  &pid_entry->memory_ranges, node) {
			char filename[128];
			snprintf(filename, 128, "%d.%lu",
				 pid_nr(pid_entry->__pid), range->start_addr);
			remove_proc_entry(filename, proc_dir);

			list_del(&range->node);
			kfree(range);
		}

		mutex_unlock(&pid_entry->range_mutex);

		put_pid(pid_entry->__pid);

		list_del(&pid_entry->node);
		kfree(pid_entry);

		printk(KERN_INFO
		       "PID entry and its memory ranges removed for PID %d.\n",
		       pid_nr(pid_entry->__pid));
		break;
	}

	mutex_unlock(&bound_list_mutex);

	remove_proc_entry(PROC_DIR_NAME, NULL);

	ambix_cleanup();
	perf_counters_disable();
	perf_counters_cleanup();
}

module_init(init);
module_exit(cleanup);
