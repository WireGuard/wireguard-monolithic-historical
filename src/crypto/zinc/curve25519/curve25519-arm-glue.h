/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/hwcap.h>
#include <asm/neon.h>
#include <asm/simd.h>

#if IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && __LINUX_ARM_ARCH__ == 7
#define ARM_USE_NEON
asmlinkage void curve25519_neon(u8 mypublic[CURVE25519_POINT_SIZE],
				const u8 secret[CURVE25519_POINT_SIZE],
				const u8 basepoint[CURVE25519_POINT_SIZE]);
#endif

static bool curve25519_use_neon __ro_after_init;

static void __init curve25519_fpu_init(void)
{
	curve25519_use_neon = elf_hwcap & HWCAP_NEON;
}

static inline bool curve25519_arch(u8 mypublic[CURVE25519_POINT_SIZE],
				   const u8 secret[CURVE25519_POINT_SIZE],
				   const u8 basepoint[CURVE25519_POINT_SIZE])
{
#ifdef ARM_USE_NEON
	if (curve25519_use_neon && may_use_simd()) {
		kernel_neon_begin();
		curve25519_neon(mypublic, secret, basepoint);
		kernel_neon_end();
		return true;
	}
#endif
	return false;
}

static inline bool curve25519_base_arch(u8 pub[CURVE25519_POINT_SIZE],
					const u8 secret[CURVE25519_POINT_SIZE])
{
	return false;
}
