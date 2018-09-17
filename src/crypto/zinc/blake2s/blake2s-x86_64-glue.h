/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>

#ifdef CONFIG_AS_AVX
asmlinkage void blake2s_compress_avx(struct blake2s_state *state,
				     const u8 *block, const size_t nblocks,
				     const u32 inc);
#endif
#ifdef CONFIG_AS_AVX512
asmlinkage void blake2s_compress_avx512(struct blake2s_state *state,
					const u8 *block, const size_t nblocks,
					const u32 inc);
#endif

static bool blake2s_use_avx __ro_after_init;
static bool blake2s_use_avx512 __ro_after_init;

static void __init blake2s_fpu_init(void)
{
	blake2s_use_avx =
		boot_cpu_has(X86_FEATURE_AVX) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
#ifndef COMPAT_CANNOT_USE_AVX512
	blake2s_use_avx512 =
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX2) &&
		boot_cpu_has(X86_FEATURE_AVX512F) &&
		boot_cpu_has(X86_FEATURE_AVX512VL) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM |
				  XFEATURE_MASK_AVX512, NULL);
#endif
}

static inline bool blake2s_arch(struct blake2s_state *state, const u8 *block,
				size_t nblocks, const u32 inc)
{
#ifdef CONFIG_AS_AVX512
	if (blake2s_use_avx512 && irq_fpu_usable()) {
		kernel_fpu_begin();
		blake2s_compress_avx512(state, block, nblocks, inc);
		kernel_fpu_end();
		return true;
	}
#endif
#ifdef CONFIG_AS_AVX
	if (blake2s_use_avx && irq_fpu_usable()) {
		kernel_fpu_begin();
		blake2s_compress_avx(state, block, nblocks, inc);
		kernel_fpu_end();
		return true;
	}
#endif
	return false;
}
