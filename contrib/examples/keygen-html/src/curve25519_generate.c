/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <emscripten.h>

typedef unsigned long long  u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef u32 __le32;

enum { CURVE25519_POINT_SIZE = 32 };

#ifndef __always_inline
#define __always_inline __inline __attribute__((__always_inline__))
#endif
#ifndef noinline
#define noinline __attribute__((noinline))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif
#ifndef __force
#define __force
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le32_to_cpup(a) (*(a))
#else
#define le32_to_cpup(a) __builtin_bswap32(*(a))
#endif

#define memset(a, b, c) __builtin_memset(a, b, c)
#define memcpy(a, b, c) __builtin_memcpy(a, b, c)
#define memmove(a, b, c) __builtin_memmove(a, b, c)
/* We don't even attempt to deal with this in javascript. */
#define memzero_explicit(a, b)

static __always_inline void normalize_secret(u8 secret[CURVE25519_POINT_SIZE])
{
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
}

#include "../../../../src/crypto/curve25519-fiat32.h"

EMSCRIPTEN_KEEPALIVE void curve25519_generate_public(u8 public[static 32], const u8 private[static 32])
{
	static const u8 basepoint[32] = { 9 };

	curve25519_generic(public, private, basepoint);
}

EMSCRIPTEN_KEEPALIVE void curve25519_generate_private(u8 private[static 32])
{
	int i;

	EM_ASM({
		/* Same trick as libsodium */
		var getRandomValue = function() {
			var buf = new Uint32Array(1);
			window.crypto.getRandomValues(buf);
			return buf[0] >>> 0;
		};
		Module.getRandomValue = getRandomValue;
	});
	
	for (i = 0; i < 32; ++i)
		private[i] = EM_ASM_INT_V({ return Module.getRandomValue(); });
	normalize_secret(private);
}

static inline void encode_base64(char dest[4], const u8 src[3])
{
	const u8 input[] = { (src[0] >> 2) & 63, ((src[0] << 4) | (src[1] >> 4)) & 63, ((src[1] << 2) | (src[2] >> 6)) & 63, src[2] & 63 };

	for (unsigned int i = 0; i < 4; ++i)
		dest[i] = input[i] + 'A'
			  + (((25 - input[i]) >> 8) & 6)
			  - (((51 - input[i]) >> 8) & 75)
			  - (((61 - input[i]) >> 8) & 15)
			  + (((62 - input[i]) >> 8) & 3);

}

EMSCRIPTEN_KEEPALIVE void key_to_base64(char base64[static 45], const u8 key[static 32])
{
	unsigned int i;

	for (i = 0; i < 32 / 3; ++i)
		encode_base64(&base64[i * 4], &key[i * 3]);
	encode_base64(&base64[i * 4], (const u8[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
	base64[45 - 2] = '=';
	base64[45 - 1] = '\0';
}
