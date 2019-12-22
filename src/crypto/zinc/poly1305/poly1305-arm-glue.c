// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/hwcap.h>
#include <asm/neon.h>

asmlinkage void poly1305_init_arm(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_arm(void *ctx, const u8 *inp, const size_t len,
				    const u32 padbit);
asmlinkage void poly1305_emit_arm(void *ctx, u8 mac[16], const u32 nonce[4]);
asmlinkage void poly1305_blocks_neon(void *ctx, const u8 *inp, const size_t len,
				     const u32 padbit);
asmlinkage void poly1305_emit_neon(void *ctx, u8 mac[16], const u32 nonce[4]);

static bool poly1305_use_neon __ro_after_init;
static bool *const poly1305_nobs[] __initconst = { &poly1305_use_neon };

static void __init poly1305_fpu_init(void)
{
#if defined(CONFIG_ZINC_ARCH_ARM64)
	poly1305_use_neon = cpu_have_named_feature(ASIMD);
#elif defined(CONFIG_ZINC_ARCH_ARM)
	poly1305_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}

static inline bool poly1305_init_arch(void *ctx,
				      const u8 key[POLY1305_KEY_SIZE])
{
	poly1305_init_arm(ctx, key);
	return true;
}

static inline bool poly1305_blocks_arch(void *ctx, const u8 *inp,
					size_t len, const u32 padbit,
					simd_context_t *simd_context)
{
	/* SIMD disables preemption, so relax after processing each page. */
	BUILD_BUG_ON(PAGE_SIZE < POLY1305_BLOCK_SIZE ||
		     PAGE_SIZE % POLY1305_BLOCK_SIZE);

	if (!IS_ENABLED(CONFIG_KERNEL_MODE_NEON) || !poly1305_use_neon ||
	    !simd_use(simd_context)) {
		convert_to_base2_64(ctx);
		poly1305_blocks_arm(ctx, inp, len, padbit);
		return true;
	}

	for (;;) {
		const size_t bytes = min_t(size_t, len, PAGE_SIZE);

		poly1305_blocks_neon(ctx, inp, bytes, padbit);
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
	if (!IS_ENABLED(CONFIG_KERNEL_MODE_NEON) || !poly1305_use_neon ||
	    !simd_use(simd_context)) {
		convert_to_base2_64(ctx);
		poly1305_emit_arm(ctx, mac, nonce);
	} else
		poly1305_emit_neon(ctx, mac, nonce);
	return true;
}
