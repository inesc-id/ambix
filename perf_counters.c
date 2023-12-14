/**
 * @file    perf_counters.c
 * @author  INESC-ID
 * @date    26 jul 2023
 * @version 2.2.0
 * @brief  Functions responsible for collecting nvram and dcpmm bandwidth usage data. intended for
 * the 5.10.0 linux kernel. Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code implemented by miguel marques
 * <miguel.soares.marques@tecnico.ulisboa.pt>
 */
#define pr_fmt(fmt) "ambix.perf_counters: " fmt
#include <linux/perf_event.h>

#include "perf_counters.h"
#include "config.h"

// CHANGE DEPENDING ON HARDWARE CONFIGURATION
static u32 CPUs[] = _CPUs; // We only read events from the CPU in numa node 0
static size_t CPUs_size = ARRAY_SIZE(CPUs);

static u32 IMCs[] = { 13, 14, 15, 16, 17, 18 };

static size_t IMCs_size = ARRAY_SIZE(IMCs);

// event numbers obtained via perf list --details
static struct counter_t COUNTERs[] = {
	{ .event = 0xe3,
	  .mult = 64,
	  .fact = 1024 * 1024,
	  .name = "PMM_READ",
	  .unit = "Mb" },
	{ .event = 0xe7,
	  .mult = 64,
	  .fact = 1024 * 1024,
	  .name = "PMM_WRITE",
	  .unit = "Mb" },

	{ .event = 0x304,
	  .mult = 64,
	  .fact = 1024 * 1024,
	  .name = "DDR_READ",
	  .unit = "Mb" },
	{ .event = 0xc04,
	  .mult = 64,
	  .fact = 1024 * 1024,
	  .name = "DDR_WRITE",
	  .unit = "Mb" },
};
static size_t COUNTERs_size = ARRAY_SIZE(COUNTERs);

static size_t *PMM_READs, *PMM_WRITEs, *DDR_READs, *DDR_WRITEs;
static uint8_t PMM_READs_size, PMM_WRITEs_size, DDR_READs_size, DDR_WRITEs_size;

struct perf_event **EVENTs = NULL;
size_t EVENTs_size = 0;

u64 *EVENTs_value = NULL;
unsigned long *EVENTs_time = NULL;
struct counter_t **EVENTs_info = NULL;

int perf_counters_init(void)
{
	struct perf_event_attr event_attr = { 0 };
	size_t imc_i, cpu_i, ctr_i, asz, event_array_length;
	int rc = 0;

	event_attr.size = sizeof(struct perf_event_attr);
	event_attr.disabled = 1;
	event_attr.sample_type = PERF_SAMPLE_IDENTIFIER;
	event_attr.read_format =
		PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
	event_attr.inherit = 1;
	event_attr.aux_output = 0;

	EVENTs_size = COUNTERs_size * IMCs_size * CPUs_size;
	EVENTs = kmalloc(sizeof(struct perf_event *) * EVENTs_size, GFP_KERNEL);
	EVENTs_value =
		kmalloc(sizeof(EVENTs_value[0]) * EVENTs_size, GFP_KERNEL);
	EVENTs_time = kmalloc(sizeof(EVENTs_time[0]) * EVENTs_size, GFP_KERNEL);
	EVENTs_info =
		kmalloc(sizeof(struct counter_t *) * EVENTs_size, GFP_KERNEL);

	PMM_READs_size = PMM_WRITEs_size = DDR_READs_size = DDR_WRITEs_size = 0;
	asz = IMCs_size * CPUs_size;
	PMM_READs = kmalloc(sizeof(PMM_READs[0]) * asz, GFP_KERNEL);
	DDR_READs = kmalloc(sizeof(DDR_READs[0]) * asz, GFP_KERNEL);
	PMM_WRITEs = kmalloc(sizeof(PMM_WRITEs[0]) * asz, GFP_KERNEL);
	DDR_WRITEs = kmalloc(sizeof(DDR_WRITEs[0]) * asz, GFP_KERNEL);

	event_array_length = EVENTs_size;
	EVENTs_size = 0;
	for (imc_i = 0; imc_i < IMCs_size; ++imc_i) {
		event_attr.type = IMCs[imc_i];
		for (cpu_i = 0; cpu_i < CPUs_size; ++cpu_i) {
			for (ctr_i = 0; ctr_i < COUNTERs_size; ++ctr_i) {
				struct perf_event *evt;
				const unsigned cpu = CPUs[cpu_i];
				struct counter_t *info = &COUNTERs[ctr_i];
				event_attr.config = info->event;

				evt = perf_event_create_kernel_counter(
					&event_attr, cpu, NULL, NULL, NULL);

				pr_debug(
					"%lu: cpu:%d; imc:%d ev:%llx; name:%s Ok:%c\n",
					EVENTs_size, cpu, event_attr.type,
					event_attr.config, info->name,
					IS_ERR(evt) ? 'N' : 'Y');

				if (IS_ERR(evt)) {
					rc = PTR_ERR(evt);
					pr_err("Perf event create on CPU %d failed with %d\n",
					       cpu, rc);
					goto cleanup;
				}

				if (EVENTs_size == event_array_length) {
					pr_err("Creating more events than allocated buffer");
					rc = -ENOMEM;
					goto cleanup;
				}

				if (!strcmp(info->name, "PMM_READ")) {
					PMM_READs[PMM_READs_size++] =
						EVENTs_size;
				} else if (!strcmp(info->name, "PMM_WRITE")) {
					PMM_WRITEs[PMM_WRITEs_size++] =
						EVENTs_size;
				} else if (!strcmp(info->name, "DDR_READ")) {
					DDR_READs[DDR_READs_size++] =
						EVENTs_size;
				} else if (!strcmp(info->name, "DDR_WRITE")) {
					DDR_WRITEs[DDR_WRITEs_size++] =
						EVENTs_size;
				}

				EVENTs_info[EVENTs_size] = info;
				EVENTs[EVENTs_size] = evt;
				++EVENTs_size;
			}
		}
	}

	return 0;

cleanup:
	perf_counters_cleanup();
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
	kfree(EVENTs_info);

	kfree(PMM_READs);
	kfree(PMM_WRITEs);
	kfree(DDR_READs);
	kfree(DDR_WRITEs);
	PMM_READs_size = PMM_WRITEs_size = DDR_READs_size = DDR_WRITEs_size = 0;

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

bool perf_counters_read_change(const size_t idx, u64 *value, u64 *time)
{
	u64 new_value, enabled, running;
	if (unlikely(idx >= EVENTs_size)) {
		pr_debug("Out of range counter %ld", idx);
		return false;
	}
	new_value = perf_event_read_value(EVENTs[idx], &enabled, &running);
	*value = new_value - EVENTs_value[idx];
	EVENTs_value[idx] = new_value;
	*time = (jiffies - EVENTs_time[idx]);
	EVENTs_time[idx] = jiffies;

	return enabled & running;
}

struct counter_t *const perf_counters_info(const size_t idx)
{
	if (unlikely(idx >= EVENTs_size)) {
		pr_debug("Out of range counter %ld", idx);
		return NULL;
	}
	return EVENTs_info[idx];
}

static u64 read_aggregate(const size_t *const aggregate, const u8 size)
{
	u8 i;
	u64 sum = 0;
	for (i = 0; i < size; ++i) {
		u64 value, time;
		const uint8_t ctr = aggregate[i];
		const struct counter_t *const info = perf_counters_info(ctr);
		if (perf_counters_read_change(ctr, &value, &time)) {
			const u64 sec = jiffies_to_sec(time);
			if (sec > 0) {
				value /= sec;
			}
			sum += (value * info->mult / info->fact);
		}
	}
	return sum;
}

u64 perf_counters_pmm_reads(void)
{
	return read_aggregate(PMM_READs, PMM_READs_size);
}

u64 perf_counters_pmm_writes(void)
{
	return read_aggregate(PMM_WRITEs, PMM_WRITEs_size);
}

u64 perf_counters_ddr_reads(void)
{
	return read_aggregate(DDR_READs, DDR_READs_size);
}

u64 perf_counters_ddr_writes(void)
{
	return read_aggregate(DDR_WRITEs, DDR_WRITEs_size);
}

void perf_counters_disable(void)
{
	size_t i;
	for (i = 0; i < EVENTs_size; ++i) {
		perf_event_disable(EVENTs[i]);
	}
	pr_debug("PCM disabled");
}

u64 jiffies_to_sec(const u64 jf)
{
	return (jf + HZ / 2) / HZ;
}
// u64 jiffies_to_sec(const u64 jf) { return jf / HZ; }
