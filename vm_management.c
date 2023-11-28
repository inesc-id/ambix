/**
 * @file    vm_management.c
 * @author  INESC-ID
 * @date    23 oct 2023
 * @version 1.0.0
 * @brief  Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code provided by reza
 * karimi <r68karimi@gmail.com>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/mm.h>

#include "vm_management.h"

DEFINE_MUTEX(VM_AREAS_LOCK);

struct vm_area_t AMBIX_VM_AREAS[MAX_VM_AREAS];
size_t VM_AREAS_COUNT = 0;

int ambix_bind_pid_constrained(const pid_t pid, unsigned long start_addr,
			       unsigned long end_addr,
			       unsigned long allocation_site,
			       unsigned long size)
{
	struct pid *pid_p = NULL;
	size_t i;
	int rc = 0;

	pid_p = find_get_pid(pid);
	if (!pid_p) {
		pr_warn("Invalid pid value (%d): can't find pid.\n", pid);
		rc = -1;
		goto out;
	}

	mutex_lock(&VM_AREAS_LOCK);

	if (VM_AREAS_COUNT == MAX_VM_AREAS) {
		pr_warn("Managed AMBIX_VM_AREAS at capacity.\n");
		rc = -1;
		goto out_unlock_put;
	}

	for (i = 0; i < VM_AREAS_COUNT; i++) {
		if (pid_nr(AMBIX_VM_AREAS[i].__pid) == pid &&
		    AMBIX_VM_AREAS[i].start_addr == start_addr &&
		    AMBIX_VM_AREAS[i].end_addr == end_addr) {
			pr_info("Already managing given vm range.\n");
			rc = -1;
			goto out_unlock_put;
		}
	}

	AMBIX_VM_AREAS[VM_AREAS_COUNT].__pid = pid_p;
	AMBIX_VM_AREAS[VM_AREAS_COUNT].start_addr = start_addr;
	AMBIX_VM_AREAS[VM_AREAS_COUNT].end_addr = end_addr;
	AMBIX_VM_AREAS[VM_AREAS_COUNT].allocation_site =
		allocation_site;
	AMBIX_VM_AREAS[VM_AREAS_COUNT].size = size;

	VM_AREAS_COUNT++;

	pr_info("Bound pid=%d with start_addr=%lx and end_addr=%lx.\n", pid,
		start_addr, end_addr);

out_unlock_put:

	if (rc == -1)
		put_pid(pid_p);

	mutex_unlock(&VM_AREAS_LOCK);

out:
	return rc;
}

int ambix_bind_pid(const pid_t nr)
{
	return ambix_bind_pid_constrained(nr, 0, MAX_ADDRESS, 0, 0);
}

int ambix_unbind_pid(const pid_t pid)
{
	size_t i;

	mutex_lock(&VM_AREAS_LOCK);

	for (i = 0; i < VM_AREAS_COUNT; i++) {
		if (pid_nr(AMBIX_VM_AREAS[i].__pid) == pid) {
			put_pid(AMBIX_VM_AREAS[i].__pid);
			AMBIX_VM_AREAS[i] =
				AMBIX_VM_AREAS[--VM_AREAS_COUNT];
		}
	}

	mutex_unlock(&VM_AREAS_LOCK);

	return 0;
}

int ambix_unbind_range_pid(const pid_t pid, unsigned long start,
			   unsigned long end)
{
	int i;

	mutex_lock(&VM_AREAS_LOCK);

	for (i = 0; i < VM_AREAS_COUNT; i++) {
		if (pid_nr(AMBIX_VM_AREAS[i].__pid) == pid &&
		    start == AMBIX_VM_AREAS[i].start_addr &&
		    end == AMBIX_VM_AREAS[i].end_addr) {
			put_pid(AMBIX_VM_AREAS[i].__pid);
			AMBIX_VM_AREAS[i] =
				AMBIX_VM_AREAS[--VM_AREAS_COUNT];

			pr_info("Unbound pid=%d.\n", pid);
			break;
		}
	}

	mutex_unlock(&VM_AREAS_LOCK);

	return 0;
}

// NB! should be called under VM_AREAS_LOCK lock
void refresh_bound_vm_areas(void)
{
	int i = 0;

	while (i < VM_AREAS_COUNT) {
		struct task_struct *t =
			get_pid_task(AMBIX_VM_AREAS[i].__pid, PIDTYPE_PID);
		if (t) {
			put_task_struct(t);
			i++;
			continue;
		}

		pr_info("Process %d has gone.\n",
			pid_nr(AMBIX_VM_AREAS[i].__pid));

		put_pid(AMBIX_VM_AREAS[i].__pid);
		AMBIX_VM_AREAS[i] = AMBIX_VM_AREAS[--VM_AREAS_COUNT];
	}
}
