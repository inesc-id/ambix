/**
 * @file
 * @author  INESC-ID
 * @date
 * @version 2.2.0
 * @brief   Adapted from the code provided by ilia kuzmin
 * <ilia.kuzmin@tecnico.ulisboa.pt>, adapted from the code provided by reza
 * karimi <r68karimi@gmail.com>, adapted from the code implemented by miguel
 * marques <miguel.soares.marques@tecnico.ulisboa.pt>
 */

#include "kernel_symbols.h"
#include "find_kallsyms_lookup_name.h"

#define M(RET, NAME, SIGNATURE)                                                \
	typedef RET(*NAME##_t) SIGNATURE;                                      \
	NAME##_t g_##NAME
#include "IMPORT.M"
#undef M

#define M(RET, NAME, SIGNATURE)                                                \
	if (!(g_##NAME = (NAME##_t)the_kallsyms_lookup_name(#NAME))) {         \
		pr_err("Can't lookup '" #NAME "' function.");                  \
		return -1;                                                     \
	}

int import_symbols(void)
{
#include "IMPORT.M"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 5)
	if (!(g_lru_disable_count = (atomic_t *)the_kallsyms_lookup_name(
		      "lru_disable_count"))) {
		pr_err("Can't lookup 'lru_disable_count' variable.");
		return -1;
	}
#endif

	return 0;
}
