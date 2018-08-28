/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_CHACHA20_H
#define _WG_CHACHA20_H

#include "simd.h"
#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/types.h>

enum {
	CHACHA20_IV_SIZE = 16,
	CHACHA20_KEY_SIZE = 32,
	CHACHA20_BLOCK_SIZE = 64,
	HCHACHA20_KEY_SIZE = 32,
	HCHACHA20_NONCE_SIZE = 16
};

struct chacha20_ctx {
	u32 key[8];
	u32 counter[4];
} __aligned(32);

void chacha20_fpu_init(void);

static inline void chacha20_init(struct chacha20_ctx *state, const u8 key[CHACHA20_KEY_SIZE], const u64 nonce)
{
	__le32 *le_key = (__le32 *)key;
	state->key[0] = get_unaligned_le32(&le_key[0]);
	state->key[1] = get_unaligned_le32(&le_key[1]);
	state->key[2] = get_unaligned_le32(&le_key[2]);
	state->key[3] = get_unaligned_le32(&le_key[3]);
	state->key[4] = get_unaligned_le32(&le_key[4]);
	state->key[5] = get_unaligned_le32(&le_key[5]);
	state->key[6] = get_unaligned_le32(&le_key[6]);
	state->key[7] = get_unaligned_le32(&le_key[7]);
	state->counter[0] = state->counter[1] = 0;
	state->counter[2] = nonce & U32_MAX;
	state->counter[3] = nonce >> 32;
}
void chacha20(struct chacha20_ctx *state, u8 *dst, const u8 *src, u32 len, simd_context_t simd_context);

void hchacha20(u8 derived_key[CHACHA20_KEY_SIZE], const u8 nonce[HCHACHA20_NONCE_SIZE], const u8 key[HCHACHA20_KEY_SIZE], simd_context_t simd_context);

#endif /* _WG_CHACHA20_H */
