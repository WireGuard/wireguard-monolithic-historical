// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Implementation of the Poly1305 message authenticator.
 *
 * Information: https://cr.yp.to/mac.html
 */

#include <zinc/poly1305.h>
#include "../selftest/run.h"

#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/init.h>

#if defined(CONFIG_ZINC_ARCH_ARM) || defined(CONFIG_ZINC_ARCH_ARM64) || defined(CONFIG_ZINC_ARCH_PPC32) || defined(CONFIG_ZINC_ARCH_PPC64)
#if defined(CONFIG_ZINC_ARCH_ARM64) || defined(CONFIG_ZINC_ARCH_PPC64)
struct poly1305_arch_internal {
	union {
		u32 h[5];
		struct {
			u64 h0, h1, h2;
		};
	};
	u64 is_base2_26;
	u64 r[2];
};
#elif defined(CONFIG_ZINC_ARCH_ARM) || defined(CONFIG_ZINC_ARCH_PPC32)
struct poly1305_arch_internal {
	union {
		u32 h[5];
		struct {
			u64 h0, h1;
			u32 h2;
		} __packed;
	};
	u32 r[4];
	u32 is_base2_26;
};
#endif
/* The NEON and AVX code uses base 2^26, while the scalar code uses base 2^64 on 64-bit
 * and base 2^32 on 32-bit. If we hit the unfortunate situation of using NEON or AVX
 * and then having to go back to scalar -- because the user is silly and has
 * called the update function from two separate contexts -- then we need to
 * convert back to the original base before proceeding. The below function is
 * written for 64-bit integers, and so we have to swap words at the end on
 * big-endian 32-bit. It is possible to reason that the initial reduction below
 * is sufficient given the implementation invariants. However, for an avoidance
 * of doubt and because this is not performance critical, we do the full
 * reduction anyway.
 */
static void convert_to_base2_64(void *ctx)
{
	struct poly1305_arch_internal *state = ctx;
	u32 cy;

	if (!(IS_ENABLED(CONFIG_KERNEL_MODE_NEON) || IS_ENABLED(CONFIG_AVX)) || !state->is_base2_26)
		return;

	cy = state->h[0] >> 26; state->h[0] &= 0x3ffffff; state->h[1] += cy;
	cy = state->h[1] >> 26; state->h[1] &= 0x3ffffff; state->h[2] += cy;
	cy = state->h[2] >> 26; state->h[2] &= 0x3ffffff; state->h[3] += cy;
	cy = state->h[3] >> 26; state->h[3] &= 0x3ffffff; state->h[4] += cy;
	state->h0 = ((u64)state->h[2] << 52) | ((u64)state->h[1] << 26) | state->h[0];
	state->h1 = ((u64)state->h[4] << 40) | ((u64)state->h[3] << 14) | (state->h[2] >> 12);
	state->h2 = state->h[4] >> 24;
	if ((IS_ENABLED(CONFIG_ZINC_ARCH_ARM) || IS_ENABLED(CONFIG_ZINC_ARCH_PPC32)) &&
	    IS_ENABLED(CONFIG_CPU_BIG_ENDIAN)) {
		state->h0 = rol64(state->h0, 32);
		state->h1 = rol64(state->h1, 32);
	}
#define ULT(a, b) ((a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1))
	cy = (state->h2 >> 2) + (state->h2 & ~3ULL);
	state->h2 &= 3;
	state->h0 += cy;
	state->h1 += (cy = ULT(state->h0, cy));
	state->h2 += ULT(state->h1, cy);
#undef ULT
	state->is_base2_26 = 0;
}
#endif

#if defined(CONFIG_ZINC_ARCH_X86_64)
#include "poly1305-x86_64-glue.c"
#elif defined(CONFIG_ZINC_ARCH_ARM) || defined(CONFIG_ZINC_ARCH_ARM64)
#include "poly1305-arm-glue.c"
#elif defined(CONFIG_ZINC_ARCH_MIPS) || defined(CONFIG_ZINC_ARCH_MIPS64)
#include "poly1305-mips-glue.c"
#elif defined(CONFIG_ZINC_ARCH_PPC32) || defined(CONFIG_ZINC_ARCH_PPC64)
#include "poly1305-ppc-glue.c"
#else
static inline bool poly1305_init_arch(void *ctx,
				      const u8 key[POLY1305_KEY_SIZE])
{
	return false;
}
static inline bool poly1305_blocks_arch(void *ctx, const u8 *input,
					size_t len, const u32 padbit,
					simd_context_t *simd_context)
{
	return false;
}
static inline bool poly1305_emit_arch(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				      const u32 nonce[4],
				      simd_context_t *simd_context)
{
	return false;
}
static bool *const poly1305_nobs[] __initconst = { };
static void __init poly1305_fpu_init(void)
{
}
#endif

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)
#include "poly1305-donna64.c"
#else
#include "poly1305-donna32.c"
#endif

void poly1305_init(struct poly1305_ctx *ctx, const u8 key[POLY1305_KEY_SIZE])
{
	ctx->nonce[0] = get_unaligned_le32(&key[16]);
	ctx->nonce[1] = get_unaligned_le32(&key[20]);
	ctx->nonce[2] = get_unaligned_le32(&key[24]);
	ctx->nonce[3] = get_unaligned_le32(&key[28]);

	if (!poly1305_init_arch(ctx->opaque, key))
		poly1305_init_generic(ctx->opaque, key);

	ctx->num = 0;
}
EXPORT_SYMBOL(poly1305_init);

static inline void poly1305_blocks(void *ctx, const u8 *input, const size_t len,
				   const u32 padbit,
				   simd_context_t *simd_context)
{
	if (!poly1305_blocks_arch(ctx, input, len, padbit, simd_context))
		poly1305_blocks_generic(ctx, input, len, padbit);
}

static inline void poly1305_emit(void *ctx, u8 mac[POLY1305_KEY_SIZE],
				 const u32 nonce[4],
				 simd_context_t *simd_context)
{
	if (!poly1305_emit_arch(ctx, mac, nonce, simd_context))
		poly1305_emit_generic(ctx, mac, nonce);
}

void poly1305_update(struct poly1305_ctx *ctx, const u8 *input, size_t len,
		     simd_context_t *simd_context)
{
	const size_t num = ctx->num;
	size_t rem;

	if (num) {
		rem = POLY1305_BLOCK_SIZE - num;
		if (len < rem) {
			memcpy(ctx->data + num, input, len);
			ctx->num = num + len;
			return;
		}
		memcpy(ctx->data + num, input, rem);
		poly1305_blocks(ctx->opaque, ctx->data, POLY1305_BLOCK_SIZE, 1,
				simd_context);
		input += rem;
		len -= rem;
	}

	rem = len % POLY1305_BLOCK_SIZE;
	len -= rem;

	if (len >= POLY1305_BLOCK_SIZE) {
		poly1305_blocks(ctx->opaque, input, len, 1, simd_context);
		input += len;
	}

	if (rem)
		memcpy(ctx->data, input, rem);

	ctx->num = rem;
}
EXPORT_SYMBOL(poly1305_update);

void poly1305_final(struct poly1305_ctx *ctx, u8 mac[POLY1305_MAC_SIZE],
		    simd_context_t *simd_context)
{
	size_t num = ctx->num;

	if (num) {
		ctx->data[num++] = 1;
		while (num < POLY1305_BLOCK_SIZE)
			ctx->data[num++] = 0;
		poly1305_blocks(ctx->opaque, ctx->data, POLY1305_BLOCK_SIZE, 0,
				simd_context);
	}

	poly1305_emit(ctx->opaque, mac, ctx->nonce, simd_context);

	memzero_explicit(ctx, sizeof(*ctx));
}
EXPORT_SYMBOL(poly1305_final);

#include "../selftest/poly1305.c"

static bool nosimd __initdata = false;

#ifndef COMPAT_ZINC_IS_A_MODULE
int __init poly1305_mod_init(void)
#else
static int __init mod_init(void)
#endif
{
	if (!nosimd)
		poly1305_fpu_init();
	if (!selftest_run("poly1305", poly1305_selftest, poly1305_nobs,
			  ARRAY_SIZE(poly1305_nobs)))
		return -ENOTRECOVERABLE;
	return 0;
}

#ifdef COMPAT_ZINC_IS_A_MODULE
static void __exit mod_exit(void)
{
}

module_param(nosimd, bool, 0);
module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Poly1305 one-time authenticator");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
#endif
