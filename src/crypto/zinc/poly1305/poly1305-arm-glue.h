/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/hwcap.h>
#include <asm/neon.h>

asmlinkage void poly1305_init_arm(void *ctx, const u8 key[16]);
asmlinkage void poly1305_blocks_arm(void *ctx, const u8 *inp, const size_t len,
				    const u32 padbit);
asmlinkage void poly1305_emit_arm(void *ctx, u8 mac[16], const u32 nonce[4]);
#if defined(CONFIG_KERNEL_MODE_NEON)
asmlinkage void poly1305_blocks_neon(void *ctx, const u8 *inp, const size_t len,
				     const u32 padbit);
asmlinkage void poly1305_emit_neon(void *ctx, u8 mac[16], const u32 nonce[4]);
#endif

static bool poly1305_use_neon __ro_after_init;

static void __init poly1305_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	poly1305_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	poly1305_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}

#if defined(CONFIG_ARM64)
struct poly1305_arch_internal {
	union {
		u32 h[5];
		struct {
			u64 h0, h1, h2;
		};
	};
	u32 is_base2_26;
	u64 r[2];
};
#elif defined(CONFIG_ARM)
struct poly1305_arch_internal {
	union {
		u32 h[5];
		struct {
			u64 h0, h1;
			u32 h2;
		} __packed;
	};
	u32 r[4];
	u32 is_base2_26;
};
#endif

#if defined(CONFIG_KERNEL_MODE_NEON)
static void convert_to_base2_64(void *ctx)
{
	struct poly1305_arch_internal *state = ctx;
	u32 cy;

	if (!state->is_base2_26)
		return;

	cy = state->h[0] >> 26; state->h[0] &= 0x3ffffff; state->h[1] += cy;
	cy = state->h[1] >> 26; state->h[1] &= 0x3ffffff; state->h[2] += cy;
	cy = state->h[2] >> 26; state->h[2] &= 0x3ffffff; state->h[3] += cy;
	cy = state->h[3] >> 26; state->h[3] &= 0x3ffffff; state->h[4] += cy;
	state->h0 = ((u64)state->h[2] << 52) | ((u64)state->h[1] << 26) | state->h[0];
	state->h1 = ((u64)state->h[4] << 40) | ((u64)state->h[3] << 14) | (state->h[2] >> 12);
	state->h2 = state->h[4] >> 24;
#define ULT(a, b) ((a ^ ((a ^ b) | ((a - b) ^ b))) >> (sizeof(a) * 8 - 1))
	cy = (state->h2 >> 2) + (state->h2 & ~3ULL);
	state->h2 &= 3;
	state->h0 += cy;
	state->h1 += (cy = ULT(state->h0, cy));
	state->h2 += ULT(state->h1, cy);
#undef ULT
	state->is_base2_26 = 0;
}
#endif

static inline bool poly1305_init_arch(void *ctx,
				      const u8 key[POLY1305_KEY_SIZE])
{
	poly1305_init_arm(ctx, key);
	return true;
}

static inline bool poly1305_blocks_arch(void *ctx, const u8 *inp,
					const size_t len, const u32 padbit,
					simd_context_t *simd_context)
{
#if defined(CONFIG_KERNEL_MODE_NEON)
	if (poly1305_use_neon && simd_use(simd_context)) {
		poly1305_blocks_neon(ctx, inp, len, padbit);
		return true;
	}
	convert_to_base2_64(ctx);
#endif

	poly1305_blocks_arm(ctx, inp, len, padbit);
	return true;
}

static inline bool poly1305_emit_arch(void *ctx, u8 mac[POLY1305_MAC_SIZE],
				      const u32 nonce[4],
				      simd_context_t *simd_context)
{
#if defined(CONFIG_KERNEL_MODE_NEON)
	if (poly1305_use_neon && simd_use(simd_context)) {
		poly1305_emit_neon(ctx, mac, nonce);
		return true;
	}
	convert_to_base2_64(ctx);
#endif

	poly1305_emit_arm(ctx, mac, nonce);
	return true;
}
