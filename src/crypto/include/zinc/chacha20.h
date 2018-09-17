/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _ZINC_CHACHA20_H
#define _ZINC_CHACHA20_H

#include <asm/unaligned.h>
#include <linux/simd.h>
#include <linux/kernel.h>
#include <linux/types.h>

enum {
	CHACHA20_IV_SIZE = 16,
	CHACHA20_KEY_SIZE = 32,
	CHACHA20_BLOCK_SIZE = 64,
	CHACHA20_BLOCK_WORDS = CHACHA20_BLOCK_SIZE / sizeof(u32),
	HCHACHA20_KEY_SIZE = 32,
	HCHACHA20_NONCE_SIZE = 16
};

struct chacha20_ctx {
	u32 key[8];
	u32 counter[4];
} __aligned(32);

static inline void chacha20_init(struct chacha20_ctx *state,
				 const u8 key[CHACHA20_KEY_SIZE],
				 const u64 nonce)
{
	state->key[0] = get_unaligned_le32(key + 0);
	state->key[1] = get_unaligned_le32(key + 4);
	state->key[2] = get_unaligned_le32(key + 8);
	state->key[3] = get_unaligned_le32(key + 12);
	state->key[4] = get_unaligned_le32(key + 16);
	state->key[5] = get_unaligned_le32(key + 20);
	state->key[6] = get_unaligned_le32(key + 24);
	state->key[7] = get_unaligned_le32(key + 28);
	state->counter[0] = state->counter[1] = 0;
	state->counter[2] = nonce & U32_MAX;
	state->counter[3] = nonce >> 32;
}
void chacha20(struct chacha20_ctx *state, u8 *dst, const u8 *src, u32 len,
	      simd_context_t *simd_context);

/* Derived key should be 32-bit aligned */
void hchacha20(u8 derived_key[CHACHA20_KEY_SIZE],
	       const u8 nonce[HCHACHA20_NONCE_SIZE],
	       const u8 key[HCHACHA20_KEY_SIZE], simd_context_t *simd_context);

#endif /* _ZINC_CHACHA20_H */
