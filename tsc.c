#define pr_fmt(fmt) "ambix.tsc: " fmt
/**
 * @file    tsc.c
 * @author  INESC-ID
 * @date    26 jul 2023
 * @version 2.2.0
 * @brief  Helper functions to convert clock cycles to seconds. Intended for
 * the 5.10.0 linux kernel. Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>
 */
#include <linux/delay.h>

#include "tsc.h"

static u64 _rdtsc_rate;

inline u64 tsc_rd(void)
{
	u32 lo, hi;
	__asm__ __volatile__("lfence;rdtsc" : "=a"(lo), "=d"(hi));
	return (u64)hi << 32 | lo;
}

void tsc_init(void)
{
	if (!_rdtsc_rate) {
		const u64 tsc = tsc_rd();
		msleep(1000);
		_rdtsc_rate = tsc_rd() - tsc;

		if (!_rdtsc_rate) {
			_rdtsc_rate = 1; // for unsupported platforms
		}
	}
}

/**
 * Convert an amount of clock cycles to msec
 *
 */
u64 tsc_to_msec(u64 tsc)
{
	if (!_rdtsc_rate) {
		tsc_init();
	}
	return tsc / (_rdtsc_rate / 1000);
}

/**
 * Convert an amount of clock cycles to msec
 *
 */
u64 tsc_to_usec(u64 tsc)
{
	if (!_rdtsc_rate) {
		tsc_init();
	}
	// drop high 10 bit to avoid operation overflow
	return ((tsc & 0x3FFFFFFFFFFFFFULL) * 1000) / (_rdtsc_rate / 1000);
}

/**
 * Convert an amount of clock cycles to nsec
 *
 */
u64 tsc_to_nsec(u64 tsc)
{
	if (!_rdtsc_rate) {
		tsc_init();
	}
	// drop high 20 bit to avoid operation overflow
	return ((tsc & 0xFFFFFFFFFFFULL) * 1000000) / (_rdtsc_rate / 1000);
}

/**
 * Convert an amount msec to clock cycles 
 *
 */
u64 tsc_from_usec(u64 usec)
{
	if (!_rdtsc_rate) {
		tsc_init();
	}

	return (usec * (_rdtsc_rate / 1000)) / 1000;
}
