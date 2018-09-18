/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/fpu/api.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/intel-family.h>

#ifdef CONFIG_AS_SSSE3
asmlinkage void hchacha20_ssse3(u8 *derived_key, const u8 *nonce,
				const u8 *key);
asmlinkage void chacha20_ssse3(u8 *out, const u8 *in, const size_t len,
			       const u32 key[8], const u32 counter[4]);
#endif
#ifdef CONFIG_AS_AVX2
asmlinkage void chacha20_avx2(u8 *out, const u8 *in, const size_t len,
			      const u32 key[8], const u32 counter[4]);
#endif
#ifdef CONFIG_AS_AVX512
asmlinkage void chacha20_avx512(u8 *out, const u8 *in, const size_t len,
				const u32 key[8], const u32 counter[4]);
asmlinkage void chacha20_avx512vl(u8 *out, const u8 *in, const size_t len,
				  const u32 key[8], const u32 counter[4]);
#endif

static bool chacha20_use_ssse3 __ro_after_init;
static bool chacha20_use_avx2 __ro_after_init;
static bool chacha20_use_avx512 __ro_after_init;
static bool chacha20_use_avx512vl __ro_after_init;

static void __init chacha20_fpu_init(void)
{
	chacha20_use_ssse3 = boot_cpu_has(X86_FEATURE_SSSE3);
	chacha20_use_avx2 =
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX2) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
#ifndef COMPAT_CANNOT_USE_AVX512
	chacha20_use_avx512 =
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX2) &&
		boot_cpu_has(X86_FEATURE_AVX512F) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM |
				  XFEATURE_MASK_AVX512, NULL) &&
		/* Skylake downclocks unacceptably much when using zmm. */
		boot_cpu_data.x86_model != INTEL_FAM6_SKYLAKE_X;
	chacha20_use_avx512vl =
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX2) &&
		boot_cpu_has(X86_FEATURE_AVX512F) &&
		boot_cpu_has(X86_FEATURE_AVX512VL) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM |
				  XFEATURE_MASK_AVX512, NULL);
#endif
}

static inline bool chacha20_arch(u8 *dst, const u8 *src, const size_t len,
				 const u32 key[8], const u32 counter[4],
				 simd_context_t *simd_context)
{
	if (!chacha20_use_ssse3 || len <= CHACHA20_BLOCK_SIZE ||
	    !simd_use(simd_context))
		return false;

#ifdef CONFIG_AS_AVX512
	if (chacha20_use_avx512 && len >= CHACHA20_BLOCK_SIZE * 8) {
		chacha20_avx512(dst, src, len, key, counter);
		return true;
	}
	if (chacha20_use_avx512vl && len >= CHACHA20_BLOCK_SIZE * 4) {
		chacha20_avx512vl(dst, src, len, key, counter);
		return true;
	}
#endif
#ifdef CONFIG_AS_AVX2
	if (chacha20_use_avx2 && len >= CHACHA20_BLOCK_SIZE * 4) {
		chacha20_avx2(dst, src, len, key, counter);
		return true;
	}
#endif
#ifdef CONFIG_AS_SSSE3
	if (chacha20_use_ssse3) {
		chacha20_ssse3(dst, src, len, key, counter);
		return true;
	}
#endif
	return false;
}

static inline bool hchacha20_arch(u8 *derived_key, const u8 *nonce,
				  const u8 *key, simd_context_t *simd_context)
{
#if defined(CONFIG_AS_SSSE3)
	if (chacha20_use_ssse3 && simd_use(simd_context)) {
		hchacha20_ssse3(derived_key, nonce, key);
		return true;
	}
#endif
	return false;
}
