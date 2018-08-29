/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is an implementation of the Curve25519 ECDH algorithm, using either
 * a 32-bit implementation or a 64-bit implementation with 128-bit integers,
 * depending on what is supported by the target compiler.
 *
 * Information: https://cr.yp.to/ecdh.html
 */

#include <zinc/curve25519.h>

#include <asm/unaligned.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/random.h>
#include <crypto/algapi.h>

#ifndef HAVE_CURVE25519_ARCH_IMPLEMENTATION
void __init curve25519_fpu_init(void)
{
}
static inline bool curve25519_arch(u8 mypublic[CURVE25519_POINT_SIZE],
				   const u8 secret[CURVE25519_POINT_SIZE],
				   const u8 basepoint[CURVE25519_POINT_SIZE])
{
	return false;
}
static inline bool curve25519_base_arch(u8 pub[CURVE25519_POINT_SIZE],
					const u8 secret[CURVE25519_POINT_SIZE])
{
	return false;
}
#endif

static __always_inline void normalize_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
}

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)
#include "curve25519-hacl64.h"
#else
#include "curve25519-fiat32.h"
#endif

static const u8 null_point[CURVE25519_POINT_SIZE] = { 0 };

bool curve25519(u8 mypublic[CURVE25519_POINT_SIZE],
		const u8 secret[CURVE25519_POINT_SIZE],
		const u8 basepoint[CURVE25519_POINT_SIZE])
{
	if (!curve25519_arch(mypublic, secret, basepoint))
		curve25519_generic(mypublic, secret, basepoint);
	return crypto_memneq(mypublic, null_point, CURVE25519_POINT_SIZE);
}
EXPORT_SYMBOL(curve25519);

bool curve25519_generate_public(u8 pub[CURVE25519_POINT_SIZE],
				const u8 secret[CURVE25519_POINT_SIZE])
{
	static const u8 basepoint[CURVE25519_POINT_SIZE] __aligned(32) = { 9 };

	if (unlikely(!crypto_memneq(secret, null_point, CURVE25519_POINT_SIZE)))
		return false;

	if (curve25519_base_arch(pub, secret))
		return crypto_memneq(pub, null_point, CURVE25519_POINT_SIZE);
	return curve25519(pub, secret, basepoint);
}
EXPORT_SYMBOL(curve25519_generate_public);

void curve25519_generate_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	get_random_bytes_wait(secret, CURVE25519_POINT_SIZE);
	normalize_secret(secret);
}
EXPORT_SYMBOL(curve25519_generate_secret);

#include "../selftest/curve25519.h"
