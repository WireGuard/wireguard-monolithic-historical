/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <zinc/poly1305.h>
#include <asm/hwcap.h>
#include <asm/neon.h>

asmlinkage void poly1305_init_arm(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_arm(void *ctx, const u8 *inp, const size_t len,
				    const u32 padbit);
asmlinkage void poly1305_emit_arm(void *ctx, u8 mac[16], const u32 nonce[4]);
#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON) &&                                     \
	(defined(CONFIG_64BIT) || __LINUX_ARM_ARCH__ >= 7)
#define ARM_USE_NEON
asmlinkage void poly1305_blocks_neon(void *ctx, const u8 *inp, const size_t len,
				     const u32 padbit);
asmlinkage void poly1305_emit_neon(void *ctx, u8 mac[16], const u32 nonce[4]);
#endif

static bool poly1305_use_neon __ro_after_init;

void __init poly1305_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	poly1305_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	poly1305_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}

static inline bool poly1305_init_arch(void *ctx,
				      const u8 key[POLY1305_KEY_SIZE],
				      simd_context_t simd_context)
{
	poly1305_init_arm(ctx, key);
	return true;
}

static inline bool poly1305_blocks_arch(void *ctx, const u8 *inp,
					const size_t len, const u32 padbit,
					simd_context_t simd_context)
{
#if defined(ARM_USE_NEON)
	if (simd_context == HAVE_FULL_SIMD && poly1305_use_neon) {
		poly1305_blocks_neon(ctx, inp, len, padbit);
		return true;
	}
#endif
	poly1305_blocks_arm(ctx, inp, len, padbit);
	return true;
}

static inline bool poly1305_emit_arch(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				      const u32 nonce[4],
				      simd_context_t simd_context)
{
#if defined(ARM_USE_NEON)
	if (simd_context == HAVE_FULL_SIMD && poly1305_use_neon) {
		poly1305_emit_neon(ctx, mac, nonce);
		return true;
	}
#endif
	poly1305_emit_arm(ctx, mac, nonce);
	return true;
}

#define HAVE_POLY1305_ARCH_IMPLEMENTATION
