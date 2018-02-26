/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <asm/hwcap.h>
#include <asm/neon.h>
#include <asm/simd.h>
asmlinkage void curve25519_neon(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE]);
static bool curve25519_use_neon __ro_after_init;
void __init curve25519_fpu_init(void)
{
	curve25519_use_neon = elf_hwcap & HWCAP_NEON;
}
