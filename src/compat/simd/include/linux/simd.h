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
	HAVE_NO_SIMD = 1 << 0,
	HAVE_FULL_SIMD = 1 << 1,
	HAVE_SIMD_IN_USE = 1 << 31
} simd_context_t;

static inline void simd_get(simd_context_t *ctx)
{
	bool have_simd = false;
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML) && !defined(CONFIG_PREEMPT_RT_BASE)
	have_simd = irq_fpu_usable();
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !defined(CONFIG_PREEMPT_RT_BASE)
#if defined(CONFIG_ARM64)
	have_simd = true; /* ARM64 supports NEON in any context. */
#elif defined(CONFIG_ARM)
	have_simd = may_use_simd(); /* ARM doesn't support NEON in interrupt context. */
#endif
#endif
	*ctx = have_simd ? HAVE_FULL_SIMD : HAVE_NO_SIMD;
}

static inline void simd_put(simd_context_t *ctx)
{
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML) && !defined(CONFIG_PREEMPT_RT_BASE)
	if (*ctx & HAVE_SIMD_IN_USE)
		kernel_fpu_end();
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !defined(CONFIG_PREEMPT_RT_BASE)
	if (*ctx & HAVE_SIMD_IN_USE)
		kernel_neon_end();
#endif
	*ctx = HAVE_NO_SIMD;
}

static inline void simd_relax(simd_context_t *ctx)
{
#ifdef CONFIG_PREEMPT
	if ((*ctx & HAVE_SIMD_IN_USE) && need_resched()) {
		simd_put(ctx);
		simd_get(ctx);
	}
#endif
}

static __must_check inline bool simd_use(simd_context_t *ctx)
{
	if (!(*ctx & HAVE_FULL_SIMD))
		return false;
	if (*ctx & HAVE_SIMD_IN_USE)
		return true;
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML) && !defined(CONFIG_PREEMPT_RT_BASE)
	kernel_fpu_begin();
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !defined(CONFIG_PREEMPT_RT_BASE)
	kernel_neon_begin();
#endif
	*ctx |= HAVE_SIMD_IN_USE;
	return true;
}

#endif /* _WG_SIMD_H */
