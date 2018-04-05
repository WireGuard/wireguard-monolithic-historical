/* SPDX-License-Identifier: OpenSSL OR (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 */

#include "chacha20poly1305.h"

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/version.h>
#include <crypto/algapi.h>
#include <crypto/scatterwalk.h>
#include <asm/unaligned.h>

#if defined(CONFIG_X86_64)
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/intel-family.h>
asmlinkage void poly1305_init_x86_64(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_x86_64(void *ctx, const u8 *inp, size_t len, u32 padbit);
asmlinkage void poly1305_emit_x86_64(void *ctx, u8 mac[16], const u32 nonce[4]);
#ifdef CONFIG_AS_SSSE3
asmlinkage void hchacha20_ssse3(u8 *derived_key, const u8 *nonce, const u8 *key);
asmlinkage void chacha20_ssse3(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
#endif
#ifdef CONFIG_AS_AVX
asmlinkage void poly1305_emit_avx(void *ctx, u8 mac[16], const u32 nonce[4]);
asmlinkage void poly1305_blocks_avx(void *ctx, const u8 *inp, size_t len, u32 padbit);
#endif
#ifdef CONFIG_AS_AVX2
asmlinkage void chacha20_avx2(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
asmlinkage void poly1305_blocks_avx2(void *ctx, const u8 *inp, size_t len, u32 padbit);
#endif
#ifdef CONFIG_AS_AVX512
asmlinkage void chacha20_avx512(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
asmlinkage void chacha20_avx512vl(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
asmlinkage void poly1305_blocks_avx512(void *ctx, const u8 *inp, size_t len, u32 padbit);
#endif

static bool chacha20poly1305_use_ssse3 __ro_after_init;
static bool chacha20poly1305_use_avx __ro_after_init;
static bool chacha20poly1305_use_avx2 __ro_after_init;
static bool chacha20poly1305_use_avx512 __ro_after_init;
static bool chacha20poly1305_use_avx512vl __ro_after_init;

void __init chacha20poly1305_fpu_init(void)
{
#ifndef CONFIG_UML
	chacha20poly1305_use_ssse3 = boot_cpu_has(X86_FEATURE_SSSE3);
	chacha20poly1305_use_avx = boot_cpu_has(X86_FEATURE_AVX) &&
				   cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
	chacha20poly1305_use_avx2 = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) &&
				    cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
#ifndef COMPAT_CANNOT_USE_AVX512
	chacha20poly1305_use_avx512 = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) &&
				      cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL) &&
				      boot_cpu_data.x86_model != INTEL_FAM6_SKYLAKE_X;
	chacha20poly1305_use_avx512vl = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) && boot_cpu_has(X86_FEATURE_AVX512VL) &&
					cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL);
#endif
#endif
}
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
asmlinkage void poly1305_init_arm(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_arm(void *ctx, const u8 *inp, size_t len, u32 padbit);
asmlinkage void poly1305_emit_arm(void *ctx, u8 mac[16], const u32 nonce[4]);
asmlinkage void chacha20_arm(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && (!defined(__LINUX_ARM_ARCH__) || __LINUX_ARM_ARCH__ >= 7)
#define ARM_USE_NEON
#include <asm/hwcap.h>
#include <asm/neon.h>
asmlinkage void poly1305_blocks_neon(void *ctx, const u8 *inp, size_t len, u32 padbit);
asmlinkage void poly1305_emit_neon(void *ctx, u8 mac[16], const u32 nonce[4]);
asmlinkage void chacha20_neon(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
#endif
static bool chacha20poly1305_use_neon __ro_after_init;
void __init chacha20poly1305_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	chacha20poly1305_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	chacha20poly1305_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}
#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
asmlinkage void poly1305_init_mips(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_mips(void *ctx, const u8 *inp, size_t len, u32 padbit);
asmlinkage void poly1305_emit_mips(void *ctx, u8 mac[16], const u32 nonce[4]);
void __init chacha20poly1305_fpu_init(void) { }
#else
void __init chacha20poly1305_fpu_init(void) { }
#endif

enum {
	CHACHA20_IV_SIZE = 16,
	CHACHA20_KEY_SIZE = 32,
	CHACHA20_BLOCK_SIZE = 64,
	POLY1305_BLOCK_SIZE = 16,
	POLY1305_KEY_SIZE = 32,
	POLY1305_MAC_SIZE = 16
};

static inline u32 le32_to_cpuvp(const void *p)
{
	return le32_to_cpup(p);
}

static inline u64 le64_to_cpuvp(const void *p)
{
	return le64_to_cpup(p);
}

struct chacha20_ctx {
	u32 state[CHACHA20_BLOCK_SIZE / sizeof(u32)];
} __aligned(32);

#define QUARTER_ROUND(x, a, b, c, d) ( \
	x[a] += x[b], \
	x[d] = rol32((x[d] ^ x[a]), 16), \
	x[c] += x[d], \
	x[b] = rol32((x[b] ^ x[c]), 12), \
	x[a] += x[b], \
	x[d] = rol32((x[d] ^ x[a]), 8), \
	x[c] += x[d], \
	x[b] = rol32((x[b] ^ x[c]), 7) \
)

#define C(i, j) (i * 4 + j)

#define DOUBLE_ROUND(x) ( \
	/* Column Round */ \
	QUARTER_ROUND(x, C(0, 0), C(1, 0), C(2, 0), C(3, 0)), \
	QUARTER_ROUND(x, C(0, 1), C(1, 1), C(2, 1), C(3, 1)), \
	QUARTER_ROUND(x, C(0, 2), C(1, 2), C(2, 2), C(3, 2)), \
	QUARTER_ROUND(x, C(0, 3), C(1, 3), C(2, 3), C(3, 3)), \
	/* Diagonal Round */ \
	QUARTER_ROUND(x, C(0, 0), C(1, 1), C(2, 2), C(3, 3)), \
	QUARTER_ROUND(x, C(0, 1), C(1, 2), C(2, 3), C(3, 0)), \
	QUARTER_ROUND(x, C(0, 2), C(1, 3), C(2, 0), C(3, 1)), \
	QUARTER_ROUND(x, C(0, 3), C(1, 0), C(2, 1), C(3, 2)) \
)

#define TWENTY_ROUNDS(x) ( \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x), \
	DOUBLE_ROUND(x) \
)

#define EXPAND_32_BYTE_K 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

static void chacha20_block_generic(struct chacha20_ctx *ctx, __le32 *stream)
{
	u32 x[CHACHA20_BLOCK_SIZE / sizeof(u32)];
	int i;

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		x[i] = ctx->state[i];

	TWENTY_ROUNDS(x);

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		stream[i] = cpu_to_le32(x[i] + ctx->state[i]);

	++ctx->state[12];
}

static void hchacha20_generic(u8 derived_key[CHACHA20POLY1305_KEYLEN], const u8 nonce[16], const u8 key[CHACHA20POLY1305_KEYLEN])
{
	__le32 *out = (__force __le32 *)derived_key;
	u32 x[] = {
		EXPAND_32_BYTE_K,
		le32_to_cpuvp(key + 0), le32_to_cpuvp(key + 4), le32_to_cpuvp(key + 8), le32_to_cpuvp(key + 12),
		le32_to_cpuvp(key + 16), le32_to_cpuvp(key + 20), le32_to_cpuvp(key + 24), le32_to_cpuvp(key + 28),
		le32_to_cpuvp(nonce +  0), le32_to_cpuvp(nonce +  4), le32_to_cpuvp(nonce +  8), le32_to_cpuvp(nonce + 12)
	};

	TWENTY_ROUNDS(x);

	out[0] = cpu_to_le32(x[0]);
	out[1] = cpu_to_le32(x[1]);
	out[2] = cpu_to_le32(x[2]);
	out[3] = cpu_to_le32(x[3]);
	out[4] = cpu_to_le32(x[12]);
	out[5] = cpu_to_le32(x[13]);
	out[6] = cpu_to_le32(x[14]);
	out[7] = cpu_to_le32(x[15]);
}

static inline void hchacha20(u8 derived_key[CHACHA20POLY1305_KEYLEN], const u8 nonce[16], const u8 key[CHACHA20POLY1305_KEYLEN], bool have_simd)
{
#if defined(CONFIG_X86_64) && defined(CONFIG_AS_SSSE3)
	if (have_simd && chacha20poly1305_use_ssse3) {
		hchacha20_ssse3(derived_key, nonce, key);
		return;
	}
#endif

	hchacha20_generic(derived_key, nonce, key);
}

#define chacha20_initial_state(key, nonce) {{ \
	EXPAND_32_BYTE_K, \
	le32_to_cpuvp((key) + 0), le32_to_cpuvp((key) + 4), le32_to_cpuvp((key) + 8), le32_to_cpuvp((key) + 12), \
	le32_to_cpuvp((key) + 16), le32_to_cpuvp((key) + 20), le32_to_cpuvp((key) + 24), le32_to_cpuvp((key) + 28), \
	0, 0, le32_to_cpuvp((nonce) +  0), le32_to_cpuvp((nonce) + 4) \
}}

static void chacha20_crypt(struct chacha20_ctx *ctx, u8 *dst, const u8 *src, u32 bytes, bool have_simd)
{
	__le32 buf[CHACHA20_BLOCK_SIZE / sizeof(__le32)];

	if (!have_simd
#if defined(CONFIG_X86_64)
		|| !chacha20poly1305_use_ssse3

#elif defined(ARM_USE_NEON)
		|| !chacha20poly1305_use_neon
#endif
	)
		goto no_simd;

#if defined(CONFIG_X86_64)
#ifdef CONFIG_AS_AVX512
	if (chacha20poly1305_use_avx512) {
		chacha20_avx512(dst, src, bytes, &ctx->state[4], &ctx->state[12]);
		ctx->state[12] += (bytes + 63) / 64;
		return;
	}
	if (chacha20poly1305_use_avx512vl) {
		chacha20_avx512vl(dst, src, bytes, &ctx->state[4], &ctx->state[12]);
		ctx->state[12] += (bytes + 63) / 64;
		return;
	}
#endif
#ifdef CONFIG_AS_AVX2
	if (chacha20poly1305_use_avx2) {
		chacha20_avx2(dst, src, bytes, &ctx->state[4], &ctx->state[12]);
		ctx->state[12] += (bytes + 63) / 64;
		return;
	}
#endif
#ifdef CONFIG_AS_SSSE3
	chacha20_ssse3(dst, src, bytes, &ctx->state[4], &ctx->state[12]);
	ctx->state[12] += (bytes + 63) / 64;
	return;
#endif
#elif defined(ARM_USE_NEON)
	chacha20_neon(dst, src, bytes, &ctx->state[4], &ctx->state[12]);
	ctx->state[12] += (bytes + 63) / 64;
	return;
#endif

no_simd:
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	chacha20_arm(dst, src, bytes, &ctx->state[4], &ctx->state[12]);
	ctx->state[12] += (bytes + 63) / 64;
	return;
#endif

	if (dst != src)
		memcpy(dst, src, bytes);

	while (bytes >= CHACHA20_BLOCK_SIZE) {
		chacha20_block_generic(ctx, buf);
		crypto_xor(dst, (u8 *)buf, CHACHA20_BLOCK_SIZE);
		bytes -= CHACHA20_BLOCK_SIZE;
		dst += CHACHA20_BLOCK_SIZE;
	}
	if (bytes) {
		chacha20_block_generic(ctx, buf);
		crypto_xor(dst, (u8 *)buf, bytes);
	}
}

struct poly1305_ctx {
	u8 opaque[24 * sizeof(u64)];
	u32 nonce[4];
	u8 data[POLY1305_BLOCK_SIZE];
	size_t num;
} __aligned(8);

#if !(defined(CONFIG_X86_64) || defined(CONFIG_ARM) || defined(CONFIG_ARM64) || (defined(CONFIG_MIPS) && defined(CONFIG_64BIT)))
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
	st->r[0] = le32_to_cpuvp(&key[ 0]) & 0x0fffffff;
	st->r[1] = le32_to_cpuvp(&key[ 4]) & 0x0ffffffc;
	st->r[2] = le32_to_cpuvp(&key[ 8]) & 0x0ffffffc;
	st->r[3] = le32_to_cpuvp(&key[12]) & 0x0ffffffc;
}

static void poly1305_blocks_generic(void *ctx, const u8 *inp, size_t len, u32 padbit)
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
		h0 = (u32)(d0 = (u64)h0 + le32_to_cpuvp(inp + 0));
		h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + le32_to_cpuvp(inp + 4));
		h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + le32_to_cpuvp(inp + 8));
		h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + le32_to_cpuvp(inp + 12));
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
		h1 += (c = CONSTANT_TIME_CARRY(h0,c));
		h2 += (c = CONSTANT_TIME_CARRY(h1,c));
		h3 += (c = CONSTANT_TIME_CARRY(h2,c));
		h4 += CONSTANT_TIME_CARRY(h3,c);
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

static void poly1305_init(struct poly1305_ctx *ctx, const u8 key[POLY1305_KEY_SIZE], bool have_simd)
{
	ctx->nonce[0] = le32_to_cpuvp(&key[16]);
	ctx->nonce[1] = le32_to_cpuvp(&key[20]);
	ctx->nonce[2] = le32_to_cpuvp(&key[24]);
	ctx->nonce[3] = le32_to_cpuvp(&key[28]);

#if defined(CONFIG_X86_64)
	poly1305_init_x86_64(ctx->opaque, key);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	poly1305_init_arm(ctx->opaque, key);
#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
	poly1305_init_mips(ctx->opaque, key);
#else
	poly1305_init_generic(ctx->opaque, key);
#endif
	ctx->num = 0;
}

static inline void poly1305_blocks(void *ctx, const u8 *inp, size_t len, u32 padbit, bool have_simd)
{
#if defined(CONFIG_X86_64)
#ifdef CONFIG_AS_AVX512
	if(chacha20poly1305_use_avx512 && have_simd)
		poly1305_blocks_avx512(ctx, inp, len, padbit);
	else
#endif
#ifdef CONFIG_AS_AVX2
	if (chacha20poly1305_use_avx2 && have_simd)
		poly1305_blocks_avx2(ctx, inp, len, padbit);
	else
#endif
#ifdef CONFIG_AS_AVX
	if (chacha20poly1305_use_avx && have_simd)
		poly1305_blocks_avx(ctx, inp, len, padbit);
	else
#endif
		poly1305_blocks_x86_64(ctx, inp, len, padbit);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#if defined(ARM_USE_NEON)
	if (chacha20poly1305_use_neon && have_simd)
		poly1305_blocks_neon(ctx, inp, len, padbit);
	else
#endif
		poly1305_blocks_arm(ctx, inp, len, padbit);
#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
	poly1305_blocks_mips(ctx, inp, len, padbit);
#else
	poly1305_blocks_generic(ctx, inp, len, padbit);
#endif
}

static inline void poly1305_emit(void *ctx, u8 mac[16], const u32 nonce[4], bool have_simd)
{
#if defined(CONFIG_X86_64)
#ifdef CONFIG_AS_AVX512
	if(chacha20poly1305_use_avx512 && have_simd)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
#ifdef CONFIG_AS_AVX2
	if (chacha20poly1305_use_avx2 && have_simd)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
#ifdef CONFIG_AS_AVX
	if (chacha20poly1305_use_avx && have_simd)
		poly1305_emit_avx(ctx, mac, nonce);
	else
#endif
		poly1305_emit_x86_64(ctx, mac, nonce);
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#if defined(ARM_USE_NEON)
	if (chacha20poly1305_use_neon && have_simd)
		poly1305_emit_neon(ctx, mac, nonce);
	else
#endif
		poly1305_emit_arm(ctx, mac, nonce);
#elif defined(CONFIG_MIPS) && defined(CONFIG_64BIT)
	poly1305_emit_mips(ctx, mac, nonce);
#else
	poly1305_emit_generic(ctx, mac, nonce);
#endif
}

static void poly1305_update(struct poly1305_ctx *ctx, const u8 *inp, size_t len, bool have_simd)
{
	const size_t num = ctx->num;
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

static void poly1305_finish(struct poly1305_ctx *ctx, u8 mac[16], bool have_simd)
{
	size_t num = ctx->num;

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


static const u8 pad0[16] = { 0 };

static struct crypto_alg chacha20_alg = {
	.cra_blocksize = 1,
	.cra_alignmask = sizeof(u32) - 1
};
static struct crypto_blkcipher chacha20_cipher = {
	.base = {
		.__crt_alg = &chacha20_alg
	}
};
static struct blkcipher_desc chacha20_desc = {
	.tfm = &chacha20_cipher
};

static inline void __chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd)
{
	__le64 len, le_nonce = cpu_to_le64(nonce);
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state = chacha20_initial_state(key, (u8 *)&le_nonce);
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0, have_simd);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	chacha20_crypt(&chacha20_state, dst, src, src_len, have_simd);

	poly1305_update(&poly1305_state, dst, src_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - src_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(src_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, dst + src_len, have_simd);

	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
}

void chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd;

	have_simd = chacha20poly1305_init_simd();
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, nonce, key, have_simd);
	chacha20poly1305_deinit_simd(have_simd);
}

bool chacha20poly1305_encrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const u8 *ad, const size_t ad_len,
				 const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
				 bool have_simd)
{
	__le64 len, le_nonce = cpu_to_le64(nonce);
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state = chacha20_initial_state(key, (u8 *)&le_nonce);
	int ret = 0;
	struct blkcipher_walk walk;
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };
	u8 mac[POLY1305_MAC_SIZE];

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0, have_simd);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	if (likely(src_len)) {
		blkcipher_walk_init(&walk, dst, src, src_len);
		ret = blkcipher_walk_virt_block(&chacha20_desc, &walk, CHACHA20_BLOCK_SIZE);
		while (walk.nbytes >= CHACHA20_BLOCK_SIZE) {
			size_t chunk_len = rounddown(walk.nbytes, CHACHA20_BLOCK_SIZE);

			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, chunk_len, have_simd);
			poly1305_update(&poly1305_state, walk.dst.virt.addr, chunk_len, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, walk.nbytes % CHACHA20_BLOCK_SIZE);
		}
		if (walk.nbytes) {
			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, walk.nbytes, have_simd);
			poly1305_update(&poly1305_state, walk.dst.virt.addr, walk.nbytes, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, 0);
		}
	}
	if (unlikely(ret))
		goto err;

	poly1305_update(&poly1305_state, pad0, (0x10 - src_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(src_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, mac, have_simd);
	scatterwalk_map_and_copy(mac, dst, src_len, sizeof(mac), 1);
err:
	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	memzero_explicit(mac, sizeof(mac));
	return !ret;
}

static inline bool __chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd)
{
	__le64 len, le_nonce = cpu_to_le64(nonce);
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state = chacha20_initial_state(key, (u8 *)&le_nonce);
	int ret;
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };
	u8 mac[POLY1305_MAC_SIZE];
	size_t dst_len;

	if (unlikely(src_len < POLY1305_MAC_SIZE))
		return false;

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0, have_simd);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	dst_len = src_len - POLY1305_MAC_SIZE;
	poly1305_update(&poly1305_state, src, dst_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - dst_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(dst_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, mac, have_simd);

	ret = crypto_memneq(mac, src + dst_len, POLY1305_MAC_SIZE);
	memzero_explicit(mac, POLY1305_MAC_SIZE);
	if (likely(!ret))
		chacha20_crypt(&chacha20_state, dst, src, dst_len, have_simd);

	memzero_explicit(&chacha20_state, sizeof(chacha20_state));

	return !ret;
}

bool chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd, ret;

	have_simd = chacha20poly1305_init_simd();
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, nonce, key, have_simd);
	chacha20poly1305_deinit_simd(have_simd);
	return ret;
}

bool chacha20poly1305_decrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const u8 *ad, const size_t ad_len,
				 const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
				 bool have_simd)
{
	__le64 len, le_nonce = cpu_to_le64(nonce);
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state = chacha20_initial_state(key, (u8 *)&le_nonce);
	struct blkcipher_walk walk;
	int ret = 0;
	u8 block0[CHACHA20_BLOCK_SIZE] = { 0 };
	u8 read_mac[POLY1305_MAC_SIZE], computed_mac[POLY1305_MAC_SIZE];
	size_t dst_len;

	if (unlikely(src_len < POLY1305_MAC_SIZE))
		return false;

	chacha20_crypt(&chacha20_state, block0, block0, sizeof(block0), have_simd);
	poly1305_init(&poly1305_state, block0, have_simd);
	memzero_explicit(block0, sizeof(block0));

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	dst_len = src_len - POLY1305_MAC_SIZE;
	if (likely(dst_len)) {
		blkcipher_walk_init(&walk, dst, src, dst_len);
		ret = blkcipher_walk_virt_block(&chacha20_desc, &walk, CHACHA20_BLOCK_SIZE);
		while (walk.nbytes >= CHACHA20_BLOCK_SIZE) {
			size_t chunk_len = rounddown(walk.nbytes, CHACHA20_BLOCK_SIZE);

			poly1305_update(&poly1305_state, walk.src.virt.addr, chunk_len, have_simd);
			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, chunk_len, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, walk.nbytes % CHACHA20_BLOCK_SIZE);
		}
		if (walk.nbytes) {
			poly1305_update(&poly1305_state, walk.src.virt.addr, walk.nbytes, have_simd);
			chacha20_crypt(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, walk.nbytes, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, 0);
		}
	}
	if (unlikely(ret))
		goto err;

	poly1305_update(&poly1305_state, pad0, (0x10 - dst_len) & 0xf, have_simd);

	len = cpu_to_le64(ad_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	len = cpu_to_le64(dst_len);
	poly1305_update(&poly1305_state, (u8 *)&len, sizeof(len), have_simd);

	poly1305_finish(&poly1305_state, computed_mac, have_simd);

	scatterwalk_map_and_copy(read_mac, src, dst_len, POLY1305_MAC_SIZE, 0);
	ret = crypto_memneq(read_mac, computed_mac, POLY1305_MAC_SIZE);
err:
	memzero_explicit(read_mac, POLY1305_MAC_SIZE);
	memzero_explicit(computed_mac, POLY1305_MAC_SIZE);
	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	return !ret;
}


void xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd = chacha20poly1305_init_simd();
	u8 derived_key[CHACHA20POLY1305_KEYLEN] __aligned(16);

	hchacha20(derived_key, nonce, key, have_simd);
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, le64_to_cpuvp(nonce + 16), derived_key, have_simd);
	memzero_explicit(derived_key, CHACHA20POLY1305_KEYLEN);
	chacha20poly1305_deinit_simd(have_simd);
}

bool xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool ret, have_simd = chacha20poly1305_init_simd();
	u8 derived_key[CHACHA20POLY1305_KEYLEN] __aligned(16);

	hchacha20(derived_key, nonce, key, have_simd);
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, le64_to_cpuvp(nonce + 16), derived_key, have_simd);
	memzero_explicit(derived_key, CHACHA20POLY1305_KEYLEN);
	chacha20poly1305_deinit_simd(have_simd);
	return ret;
}

#include "../selftest/chacha20poly1305.h"
#include "../selftest/poly1305.h"
