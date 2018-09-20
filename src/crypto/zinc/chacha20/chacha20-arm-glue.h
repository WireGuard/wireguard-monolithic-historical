/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/hwcap.h>
#include <asm/neon.h>

asmlinkage void chacha20_arm(u8 *out, const u8 *in, const size_t len,
			     const u32 key[8], const u32 counter[4]);
#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON)
#if defined(__LINUX_ARM_ARCH__) && __LINUX_ARM_ARCH__ == 7
#define ARM_USE_NEONv7
asmlinkage void chacha20_neon_1block(const u32 *state, u8 *dst, const u8 *src);
asmlinkage void chacha20_neon_4block(const u32 *state, u8 *dst, const u8 *src);
#elif defined(CONFIG_64BIT)
#define ARM_USE_NEONv8
asmlinkage void chacha20_neon(u8 *out, const u8 *in, const size_t len,
			      const u32 key[8], const u32 counter[4]);
#endif
#endif

static bool chacha20_use_neon __ro_after_init;

static void __init chacha20_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	chacha20_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	chacha20_use_neon = elf_hwcap & HWCAP_NEON;
#endif
}

static inline bool chacha20_arch(struct chacha20_ctx *state, u8 *dst,
				 const u8 *src, size_t len,
				 simd_context_t *simd_context)
{
#if defined(ARM_USE_NEONv7)
	if (chacha20_use_neon && simd_use(simd_context)) {
		u8 buf[CHACHA20_BLOCK_SIZE];

		while (len >= CHACHA20_BLOCK_SIZE * 4) {
			chacha20_neon_4block((u32 *)state, dst, src);
			len -= CHACHA20_BLOCK_SIZE * 4;
			src += CHACHA20_BLOCK_SIZE * 4;
			dst += CHACHA20_BLOCK_SIZE * 4;
			state->counter[0] += 4;
		}
		while (len >= CHACHA20_BLOCK_SIZE) {
			chacha20_neon_1block((u32 *)state, dst, src);
			len -= CHACHA20_BLOCK_SIZE;
			src += CHACHA20_BLOCK_SIZE;
			dst += CHACHA20_BLOCK_SIZE;
			state->counter[0] += 1;
		}
		if (len) {
			memcpy(buf, src, len);
			chacha20_neon_1block((u32 *)state, buf, buf);
			state->counter[0] += 1;
			memcpy(dst, buf, len);
		}
		return true;
	}
#elif defined(ARM_USE_NEONv8)
	if (chacha20_use_neon && simd_use(simd_context)) {
		chacha20_neon(dst, src, len, state->key, state->counter);
		goto success;
	}
#endif

	chacha20_arm(dst, src, len, state->key, state->counter);
	goto success;

success:
	state->counter[0] += (len + 63) / 64;
	return true;
}

static inline bool hchacha20_arch(u8 *derived_key, const u8 *nonce,
				  const u8 *key, simd_context_t *simd_context)
{
	return false;
}
