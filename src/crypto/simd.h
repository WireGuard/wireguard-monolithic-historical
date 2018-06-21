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

static inline bool simd_get(void)
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
	return have_simd;
}

static inline void simd_put(bool was_on)
{
#if defined(CONFIG_X86_64) && !defined(CONFIG_UML) && !defined(CONFIG_PREEMPT_RT_BASE)
	if (was_on)
		kernel_fpu_end();
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && !defined(CONFIG_PREEMPT_RT_BASE)
	if (was_on)
		kernel_neon_end();
#endif
}

static inline bool simd_relax(bool was_on)
{
#ifdef CONFIG_PREEMPT
	if (was_on && need_resched()) {
		simd_put(true);
		return simd_get();
	}
#endif
	return was_on;
}

#endif /* _WG_SIMD_H */
