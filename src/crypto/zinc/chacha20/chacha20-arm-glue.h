/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/hwcap.h>
#include <asm/neon.h>
#if defined(CONFIG_ARM)
#include <asm/system_info.h>
#include <asm/cputype.h>
#endif

asmlinkage void chacha20_arm(u8 *out, const u8 *in, const size_t len,
			     const u32 key[8], const u32 counter[4]);
#if defined(CONFIG_KERNEL_MODE_NEON)
asmlinkage void chacha20_neon(u8 *out, const u8 *in, const size_t len,
			      const u32 key[8], const u32 counter[4]);
#endif

static bool chacha20_use_neon __ro_after_init;

static void __init chacha20_fpu_init(void)
{
#if defined(CONFIG_ARM64)
	chacha20_use_neon = elf_hwcap & HWCAP_ASIMD;
#elif defined(CONFIG_ARM)
	switch (read_cpuid_part()) {
	case ARM_CPU_PART_CORTEX_A7:
	case ARM_CPU_PART_CORTEX_A5:
		/* The Cortex-A7 and Cortex-A5 do not perform well with the NEON
		 * implementation but do incredibly with the scalar one and use
		 * less power.
		 */
		break;
	default:
		chacha20_use_neon = elf_hwcap & HWCAP_NEON;
	}
#endif
}

static inline bool chacha20_arch(struct chacha20_ctx *state, u8 *dst,
				 const u8 *src, size_t len,
				 simd_context_t *simd_context)
{
#if defined(CONFIG_KERNEL_MODE_NEON)
	if (chacha20_use_neon && len >= CHACHA20_BLOCK_SIZE * 3 &&
	    simd_use(simd_context))
		chacha20_neon(dst, src, len, state->key, state->counter);
	else
#endif
		chacha20_arm(dst, src, len, state->key, state->counter);

	state->counter[0] += (len + 63) / 64;
	return true;
}

static inline bool hchacha20_arch(u8 *derived_key, const u8 *nonce,
				  const u8 *key, simd_context_t *simd_context)
{
	return false;
}
