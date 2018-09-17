/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

asmlinkage void chacha20_mips(u8 *out, const u8 *in, const size_t len,
			      const u32 key[8], const u32 counter[4]);
static void __init chacha20_fpu_init(void)
{
}

static inline bool chacha20_arch(u8 *dst, const u8 *src, const size_t len,
				 const u32 key[8], const u32 counter[4],
				 simd_context_t *simd_context)
{
	chacha20_mips(dst, src, len, key, counter);
	return true;
}

static inline bool hchacha20_arch(u8 *derived_key, const u8 *nonce,
				  const u8 *key, simd_context_t *simd_context)
{
	return false;
}
