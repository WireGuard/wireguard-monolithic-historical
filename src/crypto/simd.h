/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_SIMD_H
#define _WG_SIMD_H

#include <linux/sched.h>
#if defined(CONFIG_X86_64)
#include <linux/version.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON)
#include <asm/neon.h>
#include <asm/simd.h>
#endif

typedef enum {
	HAVE_NO_SIMD,
	HAVE_FULL_SIMD
} simd_context_t;

static inline simd_context_t simd_get(void)
{
	bool have_simd = false;
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML) && !defined(CONFIG_PREEMPT_RT_BASE)
	have_simd = irq_fpu_usable();
	if (have_simd)
		kernel_fpu_begin();
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !defined(CONFIG_PREEMPT_RT_BASE)
#if defined(CONFIG_ARM64)
	have_simd = true; /* ARM64 supports NEON in any context. */
#elif defined(CONFIG_ARM)
	have_simd = may_use_simd(); /* ARM doesn't support NEON in interrupt context. */
#endif
	if (have_simd)
		kernel_neon_begin();
#endif
	return have_simd ? HAVE_FULL_SIMD : HAVE_NO_SIMD;
}

static inline void simd_put(simd_context_t prior_context)
{
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML) && !defined(CONFIG_PREEMPT_RT_BASE)
	if (prior_context != HAVE_NO_SIMD)
		kernel_fpu_end();
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !defined(CONFIG_PREEMPT_RT_BASE)
	if (prior_context != HAVE_NO_SIMD)
		kernel_neon_end();
#endif
}

static inline simd_context_t simd_relax(simd_context_t prior_context)
{
#ifdef CONFIG_PREEMPT
	if (prior_context != HAVE_NO_SIMD && need_resched()) {
		simd_put(prior_context);
		return simd_get();
	}
#endif
	return prior_context;
}

#endif /* _WG_SIMD_H */
