/**
 * @file    pid_management.c
 * @author  INESC-ID
 * @date    
 * @version 
 * @brief  Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code provided by reza
 * karimi <r68karimi@gmail.com>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/mm.h>

#include "pid_management.h"

/*
-------------------------------------------------------------------------------

BIND/UNBIND FUNCTIONS

-------------------------------------------------------------------------------
*/

struct ambix_proc_t PIDs[MAX_PIDS];
size_t PIDs_size = 0;

DEFINE_MUTEX(PIDs_mtx);

int ambix_bind_pid_constrained(const pid_t nr, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size)
{
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

int ambix_bind_pid(const pid_t nr)
{
	return ambix_bind_pid_constrained(nr, 0, MAX_ADDRESS, 0, 0);
}

int ambix_unbind_pid(const pid_t nr)
{
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
			   unsigned long end)
{
	struct pid *p = NULL;
	struct mutex *m = NULL;

	size_t i;
	int rc = 0;

	mutex_lock(&PIDs_mtx);
	m = &PIDs_mtx;

	for (i = 0; i < PIDs_size; ++i) {
		if (pid_nr(PIDs[i].__pid) == nr &&
		    start == PIDs[i].start_addr && end == PIDs[i].end_addr) {
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
		struct task_struct *t =
			get_pid_task(PIDs[i].__pid, PIDTYPE_PID);
		if (t) {
			put_task_struct(t);
			continue;
		}
		pr_info("Process %d has gone.\n", pid_nr(PIDs[i].__pid));
		put_pid(PIDs[i].__pid);
		PIDs[i] = PIDs[--PIDs_size];
	}
}
