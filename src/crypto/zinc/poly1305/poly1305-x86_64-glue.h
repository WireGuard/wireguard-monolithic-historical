/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/intel-family.h>

asmlinkage void poly1305_init_x86_64(void *ctx,
				     const u8 key[POLY1305_KEY_SIZE]);
asmlinkage void poly1305_blocks_x86_64(void *ctx, const u8 *inp,
				       const size_t len, const u32 padbit);
asmlinkage void poly1305_emit_x86_64(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				     const u32 nonce[4]);
#ifdef CONFIG_AS_AVX
asmlinkage void poly1305_emit_avx(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				  const u32 nonce[4]);
asmlinkage void poly1305_blocks_avx(void *ctx, const u8 *inp, const size_t len,
				    const u32 padbit);
#endif
#ifdef CONFIG_AS_AVX2
asmlinkage void poly1305_blocks_avx2(void *ctx, const u8 *inp, const size_t len,
				     const u32 padbit);
#endif
#ifdef CONFIG_AS_AVX512
asmlinkage void poly1305_blocks_avx512(void *ctx, const u8 *inp,
				       const size_t len, const u32 padbit);
#endif

static bool poly1305_use_avx __ro_after_init;
static bool poly1305_use_avx2 __ro_after_init;
static bool poly1305_use_avx512 __ro_after_init;

static void __init poly1305_fpu_init(void)
{
	poly1305_use_avx =
		boot_cpu_has(X86_FEATURE_AVX) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
	poly1305_use_avx2 =
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX2) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
#ifndef COMPAT_CANNOT_USE_AVX512
	poly1305_use_avx512 =
		boot_cpu_has(X86_FEATURE_AVX) &&
		boot_cpu_has(X86_FEATURE_AVX2) &&
		boot_cpu_has(X86_FEATURE_AVX512F) &&
		cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM |
				  XFEATURE_MASK_AVX512, NULL) &&
		/* Skylake downclocks unacceptably much when using zmm. */
		boot_cpu_data.x86_model != INTEL_FAM6_SKYLAKE_X;
#endif
}

static inline bool poly1305_init_arch(void *ctx,
				      const u8 key[POLY1305_KEY_SIZE])
{
	poly1305_init_x86_64(ctx, key);
	return true;
}

struct poly1305_arch_internal {
	u32 h[5];
	u32 is_base2_26;
	u64 r[2];
	u64 pad;
	struct { u32 r2, r1, r4, r3; } rn[9];
};

static inline bool poly1305_blocks_arch(void *ctx, const u8 *inp,
					const size_t len, const u32 padbit,
					simd_context_t *simd_context)
{
	struct poly1305_arch_internal *state = ctx;

	if (!poly1305_use_avx ||
	    (len < (POLY1305_BLOCK_SIZE * 18) && !state->is_base2_26) ||
	    !simd_use(simd_context))
	    poly1305_blocks_x86_64(ctx, inp, len, padbit);
	else
#ifdef CONFIG_AS_AVX512
	if (poly1305_use_avx512)
		poly1305_blocks_avx512(ctx, inp, len, padbit);
	else
#endif
#ifdef CONFIG_AS_AVX2
	if (poly1305_use_avx2)
		poly1305_blocks_avx2(ctx, inp, len, padbit);
	else
#endif
#ifdef CONFIG_AS_AVX
	if (poly1305_use_avx)
		poly1305_blocks_avx(ctx, inp, len, padbit);
	else
#endif
		poly1305_blocks_x86_64(ctx, inp, len, padbit);
	return true;
}

static inline bool poly1305_emit_arch(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				      const u32 nonce[4],
				      simd_context_t *simd_context)
{
	struct poly1305_arch_internal *state = ctx;

	if (!poly1305_use_avx || !state->is_base2_26 ||!simd_use(simd_context))
		poly1305_emit_x86_64(ctx, mac, nonce);
	else
#ifdef CONFIG_AS_AVX512
	if (poly1305_use_avx512)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
#ifdef CONFIG_AS_AVX2
	if (poly1305_use_avx2)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
#ifdef CONFIG_AS_AVX
	if (poly1305_use_avx)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
		poly1305_emit_x86_64(ctx, mac, nonce);
	return true;
}
