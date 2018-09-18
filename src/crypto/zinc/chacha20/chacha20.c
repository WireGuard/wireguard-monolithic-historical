/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Implementation of the ChaCha20 stream cipher.
 *
 * Information: https://cr.yp.to/chacha.html
 */

#include <zinc/chacha20.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <crypto/algapi.h>

#if defined(CONFIG_ZINC_ARCH_X86_64)
#include "chacha20-x86_64-glue.h"
#elif defined(CONFIG_ZINC_ARCH_ARM) || defined(CONFIG_ZINC_ARCH_ARM64)
#include "chacha20-arm-glue.h"
#elif defined(CONFIG_ZINC_ARCH_MIPS)
#include "chacha20-mips-glue.h"
#else
void __init chacha20_fpu_init(void)
{
}
static inline bool chacha20_arch(u8 *out, const u8 *in, const size_t len,
				 const u32 key[8], const u32 counter[4],
				 simd_context_t *simd_context)
{
	return false;
}
static inline bool hchacha20_arch(u8 *derived_key, const u8 *nonce,
				  const u8 *key, simd_context_t *simd_context)
{
	return false;
}
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
	u32 x[CHACHA20_BLOCK_WORDS];
	int i;

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		x[i] = state[i];

	TWENTY_ROUNDS(x);

	for (i = 0; i < ARRAY_SIZE(x); ++i)
		stream[i] = cpu_to_le32(x[i] + state[i]);

	++state[12];
}

static void chacha20_generic(u8 *out, const u8 *in, u32 len, const u32 key[8],
			     const u32 counter[4])
{
	__le32 buf[CHACHA20_BLOCK_WORDS];
	u32 x[] = {
		EXPAND_32_BYTE_K,
		key[0], key[1], key[2], key[3],
		key[4], key[5], key[6], key[7],
		counter[0], counter[1], counter[2], counter[3]
	};

	if (out != in)
		memmove(out, in, len);

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

void chacha20(struct chacha20_ctx *state, u8 *dst, const u8 *src, u32 len,
	      simd_context_t *simd_context)
{
	if (!chacha20_arch(dst, src, len, state->key, state->counter,
			   simd_context))
		chacha20_generic(dst, src, len, state->key, state->counter);
	state->counter[0] += (len + 63) / 64;
}
EXPORT_SYMBOL(chacha20);

static void hchacha20_generic(u8 derived_key[CHACHA20_KEY_SIZE],
			      const u8 nonce[HCHACHA20_NONCE_SIZE],
			      const u8 key[HCHACHA20_KEY_SIZE])
{
	__le32 *out = (__force __le32 *)derived_key;
	u32 x[] = { EXPAND_32_BYTE_K,
		    get_unaligned_le32(key + 0),
		    get_unaligned_le32(key + 4),
		    get_unaligned_le32(key + 8),
		    get_unaligned_le32(key + 12),
		    get_unaligned_le32(key + 16),
		    get_unaligned_le32(key + 20),
		    get_unaligned_le32(key + 24),
		    get_unaligned_le32(key + 28),
		    get_unaligned_le32(nonce + 0),
		    get_unaligned_le32(nonce + 4),
		    get_unaligned_le32(nonce + 8),
		    get_unaligned_le32(nonce + 12)
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

/* Derived key should be 32-bit aligned */
void hchacha20(u8 derived_key[CHACHA20_KEY_SIZE],
	       const u8 nonce[HCHACHA20_NONCE_SIZE],
	       const u8 key[HCHACHA20_KEY_SIZE], simd_context_t *simd_context)
{
	if (!hchacha20_arch(derived_key, nonce, key, simd_context))
		hchacha20_generic(derived_key, nonce, key);
}
EXPORT_SYMBOL(hchacha20);

#include "../selftest/chacha20.h"

static bool nosimd __initdata = false;

#ifndef COMPAT_ZINC_IS_A_MODULE
int __init chacha20_mod_init(void)
#else
static int __init mod_init(void)
#endif
{
	if (!nosimd)
		chacha20_fpu_init();
#ifdef DEBUG
	if (!chacha20_selftest())
		return -ENOTRECOVERABLE;
#endif
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
MODULE_DESCRIPTION("ChaCha20 stream cipher");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
#endif
