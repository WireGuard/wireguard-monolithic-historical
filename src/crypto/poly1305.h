/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_POLY1305_H
#define _WG_POLY1305_H

#include <linux/types.h>

enum poly1305_lengths {
	POLY1305_BLOCK_SIZE = 16,
	POLY1305_KEY_SIZE = 32,
	POLY1305_MAC_SIZE = 16
};

struct poly1305_ctx {
	u8 opaque[24 * sizeof(u64)];
	u32 nonce[4];
	u8 data[POLY1305_BLOCK_SIZE];
	size_t num;
} __aligned(8);

void poly1305_fpu_init(void);

void poly1305_init(struct poly1305_ctx *ctx, const u8 key[POLY1305_KEY_SIZE], bool have_simd);
void poly1305_update(struct poly1305_ctx *ctx, const u8 *inp, const size_t len, bool have_simd);
void poly1305_finish(struct poly1305_ctx *ctx, u8 mac[POLY1305_MAC_SIZE], bool have_simd);

#ifdef DEBUG
bool poly1305_selftest(void);
#endif

#endif /* _WG_POLY1305_H */
