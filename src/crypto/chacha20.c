/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "chacha20.h"

#include <linux/kernel.h>
#include <crypto/algapi.h>

#if defined(CONFIG_X86_64)
#include <asm/fpu/api.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/intel-family.h>
#ifdef CONFIG_AS_SSSE3
asmlinkage void hchacha20_ssse3(u8 *derived_key, const u8 *nonce, const u8 *key);
asmlinkage void chacha20_ssse3(u8 *out, const u8 *in, const size_t len, const u32 key[8], const u32 counter[4]);
#endif
#ifdef CONFIG_AS_AVX2
asmlinkage void chacha20_avx2(u8 *out, const u8 *in, const size_t len, const u32 key[8], const u32 counter[4]);
#endif
#ifdef CONFIG_AS_AVX512
asmlinkage void chacha20_avx512(u8 *out, const u8 *in, const size_t len, const u32 key[8], const u32 counter[4]);
asmlinkage void chacha20_avx512vl(u8 *out, const u8 *in, const size_t len, const u32 key[8], const u32 counter[4]);
#endif

static bool chacha20_use_ssse3 __ro_after_init;
static bool chacha20_use_avx2 __ro_after_init;
static bool chacha20_use_avx512 __ro_after_init;
static bool chacha20_use_avx512vl __ro_after_init;

void __init chacha20_fpu_init(void)
{
#ifndef CONFIG_UML
	chacha20_use_ssse3 = boot_cpu_has(X86_FEATURE_SSSE3);
	chacha20_use_avx2 = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) &&
			    cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
#ifndef COMPAT_CANNOT_USE_AVX512
	chacha20_use_avx512 = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) &&
			      cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL) &&
			      boot_cpu_data.x86_model != INTEL_FAM6_SKYLAKE_X;
	chacha20_use_avx512vl = boot_cpu_has(X86_FEATURE_AVX) && boot_cpu_has(X86_FEATURE_AVX2) && boot_cpu_has(X86_FEATURE_AVX512F) && boot_cpu_has(X86_FEATURE_AVX512VL) &&
				cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM | XFEATURE_MASK_AVX512, NULL);
#endif
#endif
}
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
asmlinkage void chacha20_arm(u8 *out, const u8 *in, const size_t len, const u32 key[8], const u32 counter[4]);
#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && (!defined(__LINUX_ARM_ARCH__) || __LINUX_ARM_ARCH__ >= 7)
#define ARM_USE_NEON
#include <asm/hwcap.h>
#include <asm/neon.h>
asmlinkage void chacha20_neon(u8 *out, const u8 *in, const size_t len, const u32 key[8], const u32 counter[4]);
#endif
static bool chacha20_use_neon __ro_after_init;
void __init chacha20_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	chacha20_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	chacha20_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}
#elif defined(CONFIG_MIPS) && defined(CONFIG_CPU_MIPS32_R2)
asmlinkage void chacha20_mips(u8 *out, const u8 *in, const size_t len, const u32 key[8], const u32 counter[4]);
void __init chacha20_fpu_init(void) { }
#else
void __init chacha20_fpu_init(void) { }
#endif

#define EXPAND_32_BYTE_K 0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U

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

static void chacha20_block_generic(__le32 *stream, u32 *state)
{
	u32 x[CHACHA20_BLOCK_SIZE / sizeof(u32)];
	int i;

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		x[i] = state[i];

	TWENTY_ROUNDS(x);

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		stream[i] = cpu_to_le32(x[i] + state[i]);

	++state[12];
}

static void chacha20_generic(u8 *out, const u8 *in, u32 len, const u32 key[8], const u32 counter[4])
{
	__le32 buf[CHACHA20_BLOCK_SIZE / sizeof(__le32)];
	u32 x[] = {
		EXPAND_32_BYTE_K,
		key[0], key[1], key[2], key[3],
		key[4], key[5], key[6], key[7],
		counter[0], counter[1], counter[2], counter[3]
	};

	if (out != in)
		memcpy(out, in, len);

	while (len >= CHACHA20_BLOCK_SIZE) {
		chacha20_block_generic(buf, x);
		crypto_xor(out, (u8 *)buf, CHACHA20_BLOCK_SIZE);
		len -= CHACHA20_BLOCK_SIZE;
		out += CHACHA20_BLOCK_SIZE;
	}
	if (len) {
		chacha20_block_generic(buf, x);
		crypto_xor(out, (u8 *)buf, len);
	}
}

void chacha20(struct chacha20_ctx *state, u8 *dst, const u8 *src, u32 len, bool have_simd)
{
	if (!have_simd
#if defined(CONFIG_X86_64)
		|| !chacha20_use_ssse3

#elif defined(ARM_USE_NEON)
		|| !chacha20_use_neon
#endif
	)
		goto no_simd;

#if defined(CONFIG_X86_64)
#ifdef CONFIG_AS_AVX512
	if (chacha20_use_avx512) {
		chacha20_avx512(dst, src, len, state->key, state->counter);
		goto out;
	}
	if (chacha20_use_avx512vl) {
		chacha20_avx512vl(dst, src, len, state->key, state->counter);
		goto out;
	}
#endif
#ifdef CONFIG_AS_AVX2
	if (chacha20_use_avx2) {
		chacha20_avx2(dst, src, len, state->key, state->counter);
		goto out;
	}
#endif
#ifdef CONFIG_AS_SSSE3
	chacha20_ssse3(dst, src, len, state->key, state->counter);
	goto out;
#endif
#elif defined(ARM_USE_NEON)
	chacha20_neon(dst, src, len, state->key, state->counter);
	goto out;
#endif

no_simd:
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	chacha20_arm(dst, src, len, state->key, state->counter);
	goto out;
#elif defined(CONFIG_MIPS) && defined(CONFIG_CPU_MIPS32_R2)
	chacha20_mips(dst, src, len, state->key, state->counter);
	goto out;
#endif

	chacha20_generic(dst, src, len, state->key, state->counter);
	goto out;

out:
	state->counter[0] += (len + 63) / 64;
}

static void hchacha20_generic(u8 derived_key[CHACHA20_KEY_SIZE], const u8 nonce[HCHACHA20_NONCE_SIZE], const u8 key[HCHACHA20_KEY_SIZE])
{
	__le32 *out = (__force __le32 *)derived_key;
	u32 x[] = {
		EXPAND_32_BYTE_K,
		le32_to_cpup((__le32 *)(key + 0)), le32_to_cpup((__le32 *)(key + 4)), le32_to_cpup((__le32 *)(key + 8)), le32_to_cpup((__le32 *)(key + 12)),
		le32_to_cpup((__le32 *)(key + 16)), le32_to_cpup((__le32 *)(key + 20)), le32_to_cpup((__le32 *)(key + 24)), le32_to_cpup((__le32 *)(key + 28)),
		le32_to_cpup((__le32 *)(nonce + 0)), le32_to_cpup((__le32 *)(nonce + 4)), le32_to_cpup((__le32 *)(nonce +  8)), le32_to_cpup((__le32 *)(nonce + 12))
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

void hchacha20(u8 derived_key[CHACHA20_KEY_SIZE], const u8 nonce[HCHACHA20_NONCE_SIZE], const u8 key[HCHACHA20_KEY_SIZE], bool have_simd)
{
#if defined(CONFIG_X86_64) && defined(CONFIG_AS_SSSE3)
	if (have_simd && chacha20_use_ssse3) {
		hchacha20_ssse3(derived_key, nonce, key);
		return;
	}
#endif
	hchacha20_generic(derived_key, nonce, key);
}
