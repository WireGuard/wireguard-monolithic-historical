/* SPDX-License-Identifier: OpenSSL OR (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 */

#include "poly1305.h"

#include <linux/kernel.h>

#if defined(CONFIG_X86_64)
#include <asm/fpu/api.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/intel-family.h>
asmlinkage void poly1305_init_x86_64(void *ctx, const u8 key[POLY1305_KEY_SIZE]);
asmlinkage void poly1305_blocks_x86_64(void *ctx, const u8 *inp, const size_t len, const u32 padbit);
asmlinkage void poly1305_emit_x86_64(void *ctx, u8 mac[POLY1305_MAC_SIZE], const u32 nonce[4]);
#ifdef CONFIG_AS_AVX
asmlinkage void poly1305_emit_avx(void *ctx, u8 mac[POLY1305_MAC_SIZE], const u32 nonce[4]);
asmlinkage void poly1305_blocks_avx(void *ctx, const u8 *inp, const size_t len, const u32 padbit);
#endif
#ifdef CONFIG_AS_AVX2
asmlinkage void poly1305_blocks_avx2(void *ctx, const u8 *inp, const size_t len, const u32 padbit);
#endif
#ifdef CONFIG_AS_AVX512
asmlinkage void poly1305_blocks_avx512(void *ctx, const u8 *inp, const size_t len, const u32 padbit);
#endif

static bool poly1305_use_avx __ro_after_init;
static bool poly1305_use_avx2 __ro_after_init;
static bool poly1305_use_avx512 __ro_after_init;

void __init poly1305_fpu_init(void)
{
#ifndef CONFIG_UML
	poly1305_use_avx = boot_cpu_has(X86_FEATURE_AVX) &&
			   cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
	poly1305_use_avx2 = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) &&
			    cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
#ifndef COMPAT_CANNOT_USE_AVX512
	poly1305_use_avx512 = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) &&
			      cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL) &&
			      boot_cpu_data.x86_model != INTEL_FAM6_SKYLAKE_X;
#endif
#endif
}
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
asmlinkage void poly1305_init_arm(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_arm(void *ctx, const u8 *inp, const size_t len, const u32 padbit);
asmlinkage void poly1305_emit_arm(void *ctx, u8 mac[16], const u32 nonce[4]);
#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && (!defined(__LINUX_ARM_ARCH__) || __LINUX_ARM_ARCH__ >= 7)
#define ARM_USE_NEON
#include <asm/hwcap.h>
#include <asm/neon.h>
asmlinkage void poly1305_blocks_neon(void *ctx, const u8 *inp, const size_t len, const u32 padbit);
asmlinkage void poly1305_emit_neon(void *ctx, u8 mac[16], const u32 nonce[4]);
#endif
static bool poly1305_use_neon __ro_after_init;
void __init poly1305_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	poly1305_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	poly1305_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}
#elif defined(CONFIG_MIPS) && (defined(CONFIG_64BIT) || defined(CONFIG_CPU_MIPS32_R2))
asmlinkage void poly1305_init_mips(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_mips(void *ctx, const u8 *inp, const size_t len, const u32 padbit);
asmlinkage void poly1305_emit_mips(void *ctx, u8 mac[16], const u32 nonce[4]);
void __init poly1305_fpu_init(void) { }
#else
void __init poly1305_fpu_init(void) { }
#endif

#if !(defined(CONFIG_X86_64) || defined(CONFIG_ARM) || defined(CONFIG_ARM64) || (defined(CONFIG_MIPS) && (defined(CONFIG_64BIT) || defined(CONFIG_CPU_MIPS32_R2))))
struct poly1305_internal {
	u32 h[5];
	u32 r[4];
};

static void poly1305_init_generic(void *ctx, const u8 key[16])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	st->r[0] = le32_to_cpup((__le32 *)&key[ 0]) & 0x0fffffff;
	st->r[1] = le32_to_cpup((__le32 *)&key[ 4]) & 0x0ffffffc;
	st->r[2] = le32_to_cpup((__le32 *)&key[ 8]) & 0x0ffffffc;
	st->r[3] = le32_to_cpup((__le32 *)&key[12]) & 0x0ffffffc;
}

static void poly1305_blocks_generic(void *ctx, const u8 *inp, size_t len, const u32 padbit)
{
#define CONSTANT_TIME_CARRY(a,b) ((a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1))
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	u32 r0, r1, r2, r3;
	u32 s1, s2, s3;
	u32 h0, h1, h2, h3, h4, c;
	u64 d0, d1, d2, d3;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];

	s1 = r1 + (r1 >> 2);
	s2 = r2 + (r2 >> 2);
	s3 = r3 + (r3 >> 2);

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (len >= POLY1305_BLOCK_SIZE) {
		/* h += m[i] */
		h0 = (u32)(d0 = (u64)h0 + le32_to_cpup((__le32 *)(inp + 0)));
		h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + le32_to_cpup((__le32 *)(inp + 4)));
		h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + le32_to_cpup((__le32 *)(inp + 8)));
		h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + le32_to_cpup((__le32 *)(inp + 12)));
		h4 += (u32)(d3 >> 32) + padbit;

		/* h *= r "%" p, where "%" stands for "partial remainder" */
		d0 = ((u64)h0 * r0) +
		     ((u64)h1 * s3) +
		     ((u64)h2 * s2) +
		     ((u64)h3 * s1);
		d1 = ((u64)h0 * r1) +
		     ((u64)h1 * r0) +
		     ((u64)h2 * s3) +
		     ((u64)h3 * s2) +
		     (h4 * s1);
		d2 = ((u64)h0 * r2) +
		     ((u64)h1 * r1) +
		     ((u64)h2 * r0) +
		     ((u64)h3 * s3) +
		     (h4 * s2);
		d3 = ((u64)h0 * r3) +
		     ((u64)h1 * r2) +
		     ((u64)h2 * r1) +
		     ((u64)h3 * r0) +
		     (h4 * s3);
		h4 = (h4 * r0);

		/* last reduction step: */
		/* a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0 */
		h0 = (u32)d0;
		h1 = (u32)(d1 += d0 >> 32);
		h2 = (u32)(d2 += d1 >> 32);
		h3 = (u32)(d3 += d2 >> 32);
		h4 += (u32)(d3 >> 32);
		/* b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130 */
		c = (h4 >> 2) + (h4 & ~3U);
		h4 &= 3;
		h0 += c;
		h1 += (c = CONSTANT_TIME_CARRY(h0, c));
		h2 += (c = CONSTANT_TIME_CARRY(h1, c));
		h3 += (c = CONSTANT_TIME_CARRY(h2, c));
		h4 += CONSTANT_TIME_CARRY(h3, c);
		/*
		 * Occasional overflows to 3rd bit of h4 are taken care of
		 * "naturally". If after this point we end up at the top of
		 * this loop, then the overflow bit will be accounted for
		 * in next iteration. If we end up in poly1305_emit, then
		 * comparison to modulus below will still count as "carry
		 * into 131st bit", so that properly reduced value will be
		 * picked in conditional move.
		 */

		inp += POLY1305_BLOCK_SIZE;
		len -= POLY1305_BLOCK_SIZE;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
#undef CONSTANT_TIME_CARRY
}

static void poly1305_emit_generic(void *ctx, u8 mac[16], const u32 nonce[4])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	__le32 *omac = (__force __le32 *)mac;
	u32 h0, h1, h2, h3, h4;
	u32 g0, g1, g2, g3, g4;
	u64 t;
	u32 mask;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	/* compare to modulus by computing h + -p */
	g0 = (u32)(t = (u64)h0 + 5);
	g1 = (u32)(t = (u64)h1 + (t >> 32));
	g2 = (u32)(t = (u64)h2 + (t >> 32));
	g3 = (u32)(t = (u64)h3 + (t >> 32));
	g4 = h4 + (u32)(t >> 32);

	/* if there was carry into 131st bit, h3:h0 = g3:g0 */
	mask = 0 - (g4 >> 2);
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;

	/* mac = (h + nonce) % (2^128) */
	h0 = (u32)(t = (u64)h0 + nonce[0]);
	h1 = (u32)(t = (u64)h1 + (t >> 32) + nonce[1]);
	h2 = (u32)(t = (u64)h2 + (t >> 32) + nonce[2]);
	h3 = (u32)(t = (u64)h3 + (t >> 32) + nonce[3]);

	omac[0] = cpu_to_le32(h0);
	omac[1] = cpu_to_le32(h1);
	omac[2] = cpu_to_le32(h2);
	omac[3] = cpu_to_le32(h3);
}
#endif

void poly1305_init(struct poly1305_ctx *ctx, const u8 key[POLY1305_KEY_SIZE], bool have_simd)
{
	ctx->nonce[0] = le32_to_cpup((__le32 *)&key[16]);
	ctx->nonce[1] = le32_to_cpup((__le32 *)&key[20]);
	ctx->nonce[2] = le32_to_cpup((__le32 *)&key[24]);
	ctx->nonce[3] = le32_to_cpup((__le32 *)&key[28]);

#if defined(CONFIG_X86_64)
	poly1305_init_x86_64(ctx->opaque, key);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	poly1305_init_arm(ctx->opaque, key);
#elif defined(CONFIG_MIPS) && (defined(CONFIG_64BIT) || defined(CONFIG_CPU_MIPS32_R2))
	poly1305_init_mips(ctx->opaque, key);
#else
	poly1305_init_generic(ctx->opaque, key);
#endif
	ctx->num = 0;
}

static inline void poly1305_blocks(void *ctx, const u8 *inp, const size_t len, const u32 padbit, bool have_simd)
{
#if defined(CONFIG_X86_64)
#ifdef CONFIG_AS_AVX512
	if (poly1305_use_avx512 && have_simd)
		poly1305_blocks_avx512(ctx, inp, len, padbit);
	else
#endif
#ifdef CONFIG_AS_AVX2
	if (poly1305_use_avx2 && have_simd)
		poly1305_blocks_avx2(ctx, inp, len, padbit);
	else
#endif
#ifdef CONFIG_AS_AVX
	if (poly1305_use_avx && have_simd)
		poly1305_blocks_avx(ctx, inp, len, padbit);
	else
#endif
		poly1305_blocks_x86_64(ctx, inp, len, padbit);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#if defined(ARM_USE_NEON)
	if (poly1305_use_neon && have_simd)
		poly1305_blocks_neon(ctx, inp, len, padbit);
	else
#endif
		poly1305_blocks_arm(ctx, inp, len, padbit);
#elif defined(CONFIG_MIPS) && (defined(CONFIG_64BIT) || defined(CONFIG_CPU_MIPS32_R2))
	poly1305_blocks_mips(ctx, inp, len, padbit);
#else
	poly1305_blocks_generic(ctx, inp, len, padbit);
#endif
}

static inline void poly1305_emit(void *ctx, u8 mac[POLY1305_KEY_SIZE], const u32 nonce[4], bool have_simd)
{
#if defined(CONFIG_X86_64)
#ifdef CONFIG_AS_AVX512
	if (poly1305_use_avx512 && have_simd)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
#ifdef CONFIG_AS_AVX2
	if (poly1305_use_avx2 && have_simd)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
#ifdef CONFIG_AS_AVX
	if (poly1305_use_avx && have_simd)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
		poly1305_emit_x86_64(ctx, mac, nonce);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#if defined(ARM_USE_NEON)
	if (poly1305_use_neon && have_simd)
		poly1305_emit_neon(ctx, mac, nonce);
	else
#endif
		poly1305_emit_arm(ctx, mac, nonce);
#elif defined(CONFIG_MIPS) && (defined(CONFIG_64BIT) || defined(CONFIG_CPU_MIPS32_R2))
	poly1305_emit_mips(ctx, mac, nonce);
#else
	poly1305_emit_generic(ctx, mac, nonce);
#endif
}

void poly1305_update(struct poly1305_ctx *ctx, const u8 *inp, size_t len, bool have_simd)
{
	const size_t num = ctx->num % POLY1305_BLOCK_SIZE;
	size_t rem;

	if (num) {
		rem = POLY1305_BLOCK_SIZE - num;
		if (len >= rem) {
			memcpy(ctx->data + num, inp, rem);
			poly1305_blocks(ctx->opaque, ctx->data, POLY1305_BLOCK_SIZE, 1, have_simd);
			inp += rem;
			len -= rem;
		} else {
			/* Still not enough data to process a block. */
			memcpy(ctx->data + num, inp, len);
			ctx->num = num + len;
			return;
		}
	}

	rem = len % POLY1305_BLOCK_SIZE;
	len -= rem;

	if (len >= POLY1305_BLOCK_SIZE) {
		poly1305_blocks(ctx->opaque, inp, len, 1, have_simd);
		inp += len;
	}

	if (rem)
		memcpy(ctx->data, inp, rem);

	ctx->num = rem;
}

void poly1305_finish(struct poly1305_ctx *ctx, u8 mac[POLY1305_MAC_SIZE], bool have_simd)
{
	size_t num = ctx->num % POLY1305_BLOCK_SIZE;

	if (num) {
		ctx->data[num++] = 1;   /* pad bit */
		while (num < POLY1305_BLOCK_SIZE)
			ctx->data[num++] = 0;
		poly1305_blocks(ctx->opaque, ctx->data, POLY1305_BLOCK_SIZE, 0, have_simd);
	}

	poly1305_emit(ctx->opaque, mac, ctx->nonce, have_simd);

	/* zero out the state */
	memzero_explicit(ctx, sizeof(*ctx));
}

#include "../selftest/poly1305.h"
