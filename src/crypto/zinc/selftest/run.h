/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _ZINC_SELFTEST_RUN_H
#define _ZINC_SELFTEST_RUN_H

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/bug.h>

static inline bool selftest_run(const char *name, bool (*selftest)(void),
				bool *const nobs[], unsigned int nobs_len)
{
	unsigned long subset = 0, set = 0;
	unsigned int i;
	bool ret = true;

	BUILD_BUG_ON(!__builtin_constant_p(nobs_len) ||
		     nobs_len >= BITS_PER_LONG);

	if (!IS_ENABLED(CONFIG_ZINC_SELFTEST))
		return true;

	for (i = 0; i < nobs_len; ++i)
		set |= ((unsigned long)*nobs[i]) << i;

	do {
		for (i = 0; i < nobs_len; ++i)
			*nobs[i] = (subset >> i) & 1;
		if (!selftest()) {
			pr_err("%s self-test combo 0x%lx: FAIL\n", name,
			       subset);
			ret = false;
		}
		subset = (subset - set) & set;
	} while (subset);

	for (i = 0; i < nobs_len; ++i)
		*nobs[i] = (set >> i) & 1;

	if (ret)
		pr_info("%s self-tests: pass\n", name);

	return !WARN_ON(!ret);
}

#endif
