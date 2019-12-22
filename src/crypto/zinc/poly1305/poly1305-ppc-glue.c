// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2019 Shawn Landden <shawn@git.icu>. All Rights Reserved.
 */

#include <asm/cpufeature.h>

asmlinkage void poly1305_init_int(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_int(void *ctx, const u8 *inp, size_t len,
				    u32 padbit);
asmlinkage void poly1305_emit_int(void *ctx, u8 mac[16],
				  const u32 nonce[4]);
asmlinkage void poly1305_blocks_vsx(void *ctx, const u8 *inp, size_t len,
				    u32 padbit);
static bool *const poly1305_nobs[] __initconst = {};
static void __init poly1305_fpu_init(void) {}

static inline bool poly1305_init_arch(void *ctx,
				      const u8 key[POLY1305_KEY_SIZE])
{
	poly1305_init_int(ctx, key);
	return true;
}

static inline bool poly1305_blocks_arch(void *ctx, const u8 *inp,
					size_t len, const u32 padbit,
					simd_context_t *simd_context)
{
	/* SIMD disables preemption, so relax after processing each page. */
	BUILD_BUG_ON(PAGE_SIZE < POLY1305_BLOCK_SIZE ||
		     PAGE_SIZE % POLY1305_BLOCK_SIZE);

	if (!IS_ENABLED(CONFIG_VSX) ||
	    !cpu_have_feature(PPC_MODULE_FEATURE_VEC_CRYPTO) ||
	    !simd_use(simd_context)) {
		convert_to_base2_64(ctx);
		poly1305_blocks_int(ctx, inp, len, padbit);
		return true;
	}

	for (;;) {
		const size_t bytes = min_t(size_t, len, PAGE_SIZE);

		poly1305_blocks_vsx(ctx, inp, bytes, padbit);
		len -= bytes;
		if (!len)
			break;
		inp += bytes;
		simd_relax(simd_context);
	}
	return true;
}

static inline bool poly1305_emit_arch(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				      const u32 nonce[4],
				      simd_context_t *simd_context)
{
	poly1305_emit_int(ctx, mac, nonce);
	return true;
}
