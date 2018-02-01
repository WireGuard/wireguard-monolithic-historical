/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "curve25519.h"

#include <linux/version.h>
#include <linux/string.h>
#include <linux/random.h>
#include <crypto/algapi.h>

static __always_inline void normalize_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
}

#if defined(CONFIG_X86_64) && defined(CONFIG_AS_AVX)
#include "curve25519-x86_64.h"
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && defined(CONFIG_ARM)
#include "curve25519-arm.h"
#else
void __init curve25519_fpu_init(void) { }
#endif

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)
#include "curve25519-hacl64.h"
#else
#include "curve25519-fiat32.h"
#endif

static const u8 null_point[CURVE25519_POINT_SIZE] = { 0 };

bool curve25519(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE])
{
#if defined(CONFIG_X86_64) && defined(CONFIG_AS_AVX)
	if (curve25519_use_avx && irq_fpu_usable()) {
		kernel_fpu_begin();
		curve25519_sandy2x(mypublic, secret, basepoint);
		kernel_fpu_end();
	} else
#elif IS_ENABLED(CONFIG_KERNEL_MODE_NEON) && defined(CONFIG_ARM)
	if (curve25519_use_neon && may_use_simd()) {
		kernel_neon_begin();
		curve25519_neon(mypublic, secret, basepoint);
		kernel_neon_end();
	} else
#endif
		curve25519_generic(mypublic, secret, basepoint);

	return crypto_memneq(mypublic, null_point, CURVE25519_POINT_SIZE);
}

bool curve25519_generate_public(u8 pub[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE])
{
	static const u8 basepoint[CURVE25519_POINT_SIZE] __aligned(32) = { 9 };

	if (unlikely(!crypto_memneq(secret, null_point, CURVE25519_POINT_SIZE)))
		return false;

#if defined(CONFIG_X86_64) && defined(CONFIG_AS_AVX)
	if (curve25519_use_avx && irq_fpu_usable()) {
		kernel_fpu_begin();
		curve25519_sandy2x_base(pub, secret);
		kernel_fpu_end();
		return crypto_memneq(pub, null_point, CURVE25519_POINT_SIZE);
	}
#endif

	return curve25519(pub, secret, basepoint);
}

void curve25519_generate_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	get_random_bytes_wait(secret, CURVE25519_POINT_SIZE);
	normalize_secret(secret);
}

#include "../selftest/curve25519.h"
