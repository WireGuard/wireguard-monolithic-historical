/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Implementation of the Poly1305 message authenticator.
 *
 * Information: https://cr.yp.to/mac.html
 */

#include <zinc/poly1305.h>

#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/string.h>

#ifndef HAVE_POLY1305_ARCH_IMPLEMENTATION
static inline bool poly1305_init_arch(void *ctx,
				      const u8 key[POLY1305_KEY_SIZE],
				      simd_context_t simd_context)
{
	return false;
}
static inline bool poly1305_blocks_arch(void *ctx, const u8 *input,
					const size_t len, const u32 padbit,
					simd_context_t simd_context)
{
	return false;
}
static inline bool poly1305_emit_arch(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				      const u32 nonce[4],
				      simd_context_t simd_context)
{
	return false;
}
void __init poly1305_fpu_init(void)
{
}
#endif

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)
#include "poly1305-donna64.h"
#else
#include "poly1305-donna32.h"
#endif

void poly1305_init(struct poly1305_ctx *ctx, const u8 key[POLY1305_KEY_SIZE],
		   simd_context_t simd_context)
{
	ctx->nonce[0] = get_unaligned_le32(&key[16]);
	ctx->nonce[1] = get_unaligned_le32(&key[20]);
	ctx->nonce[2] = get_unaligned_le32(&key[24]);
	ctx->nonce[3] = get_unaligned_le32(&key[28]);

	if (!poly1305_init_arch(ctx->opaque, key, simd_context))
		poly1305_init_generic(ctx->opaque, key);

	ctx->num = 0;
}
EXPORT_SYMBOL(poly1305_init);

static inline void poly1305_blocks(void *ctx, const u8 *input, const size_t len,
				   const u32 padbit,
				   simd_context_t simd_context)
{
	if (!poly1305_blocks_arch(ctx, input, len, padbit, simd_context))
		poly1305_blocks_generic(ctx, input, len, padbit);
}

static inline void poly1305_emit(void *ctx, u8 mac[POLY1305_KEY_SIZE],
				 const u32 nonce[4],
				 simd_context_t simd_context)
{
	if (!poly1305_emit_arch(ctx, mac, nonce, simd_context))
		poly1305_emit_generic(ctx, mac, nonce);
}

void poly1305_update(struct poly1305_ctx *ctx, const u8 *input, size_t len,
		     simd_context_t simd_context)
{
	const size_t num = ctx->num % POLY1305_BLOCK_SIZE;
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

void poly1305_finish(struct poly1305_ctx *ctx, u8 mac[POLY1305_MAC_SIZE],
		     simd_context_t simd_context)
{
	size_t num = ctx->num % POLY1305_BLOCK_SIZE;

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
EXPORT_SYMBOL(poly1305_finish);

#include "../selftest/poly1305.h"
