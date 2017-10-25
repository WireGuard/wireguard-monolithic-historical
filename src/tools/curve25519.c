/* Original author: Adam Langley <agl@imperialviolet.org>
 *
 * Copyright 2008 Google Inc. All Rights Reserved.
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 *   Redistribution and use in source and binary forms of this file, with or
 *   without modification, are permitted provided that the following conditions
 *   are met:
 *
 *       * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *       * Neither the name of Google Inc nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "curve25519.h"

#include <stdint.h>
#include <string.h>

#ifndef __always_inline
#define __always_inline __inline __attribute__((__always_inline__))
#endif

#ifdef __SIZEOF_INT128__
typedef uint64_t limb;
typedef limb felem[5];
typedef __uint128_t uint128_t;

/* Sum two numbers: output += in */
static __always_inline void fsum(limb *output, const limb *in)
{
	output[0] += in[0];
	output[1] += in[1];
	output[2] += in[2];
	output[3] += in[3];
	output[4] += in[4];
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!)
 *
 * Assumes that out[i] < 2**52
 * On return, out[i] < 2**55
 */
static __always_inline void fdifference_backwards(felem out, const felem in)
{
	/* 152 is 19 << 3 */
	static const limb two54m152 = (((limb)1) << 54) - 152;
	static const limb two54m8 = (((limb)1) << 54) - 8;

	out[0] = in[0] + two54m152 - out[0];
	out[1] = in[1] + two54m8 - out[1];
	out[2] = in[2] + two54m8 - out[2];
	out[3] = in[3] + two54m8 - out[3];
	out[4] = in[4] + two54m8 - out[4];
}

/* Multiply a number by a scalar: output = in * scalar */
static __always_inline void fscalar_product(felem output, const felem in, const limb scalar)
{
	uint128_t a;

	a = ((uint128_t) in[0]) * scalar;
	output[0] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((uint128_t) in[1]) * scalar + ((limb) (a >> 51));
	output[1] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((uint128_t) in[2]) * scalar + ((limb) (a >> 51));
	output[2] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((uint128_t) in[3]) * scalar + ((limb) (a >> 51));
	output[3] = ((limb)a) & 0x7ffffffffffffUL;

	a = ((uint128_t) in[4]) * scalar + ((limb) (a >> 51));
	output[4] = ((limb)a) & 0x7ffffffffffffUL;

	output[0] += (a >> 51) * 19;
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, output[i] < 2**52
 */
static __always_inline void fmul(felem output, const felem in2, const felem in)
{
	uint128_t t[5];
	limb r0, r1, r2, r3, r4, s0, s1, s2, s3, s4, c;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	s0 = in2[0];
	s1 = in2[1];
	s2 = in2[2];
	s3 = in2[3];
	s4 = in2[4];

	t[0]  =  ((uint128_t) r0) * s0;
	t[1]  =  ((uint128_t) r0) * s1 + ((uint128_t) r1) * s0;
	t[2]  =  ((uint128_t) r0) * s2 + ((uint128_t) r2) * s0 + ((uint128_t) r1) * s1;
	t[3]  =  ((uint128_t) r0) * s3 + ((uint128_t) r3) * s0 + ((uint128_t) r1) * s2 + ((uint128_t) r2) * s1;
	t[4]  =  ((uint128_t) r0) * s4 + ((uint128_t) r4) * s0 + ((uint128_t) r3) * s1 + ((uint128_t) r1) * s3 + ((uint128_t) r2) * s2;

	r4 *= 19;
	r1 *= 19;
	r2 *= 19;
	r3 *= 19;

	t[0] += ((uint128_t) r4) * s1 + ((uint128_t) r1) * s4 + ((uint128_t) r2) * s3 + ((uint128_t) r3) * s2;
	t[1] += ((uint128_t) r4) * s2 + ((uint128_t) r2) * s4 + ((uint128_t) r3) * s3;
	t[2] += ((uint128_t) r4) * s3 + ((uint128_t) r3) * s4;
	t[3] += ((uint128_t) r4) * s4;

			r0 = (limb)t[0] & 0x7ffffffffffffUL; c = (limb)(t[0] >> 51);
	t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffffUL; c = (limb)(t[1] >> 51);
	t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffffUL; c = (limb)(t[2] >> 51);
	t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffffUL; c = (limb)(t[3] >> 51);
	t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffffUL; c = (limb)(t[4] >> 51);
	r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffffUL;
	r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffffUL;
	r2 +=   c;

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}

static __always_inline void fsquare_times(felem output, const felem in, limb count)
{
	uint128_t t[5];
	limb r0, r1, r2, r3, r4, c;
	limb d0, d1, d2, d4, d419;

	r0 = in[0];
	r1 = in[1];
	r2 = in[2];
	r3 = in[3];
	r4 = in[4];

	do {
		d0 = r0 * 2;
		d1 = r1 * 2;
		d2 = r2 * 2 * 19;
		d419 = r4 * 19;
		d4 = d419 * 2;

		t[0] = ((uint128_t) r0) * r0 + ((uint128_t) d4) * r1 + (((uint128_t) d2) * (r3     ));
		t[1] = ((uint128_t) d0) * r1 + ((uint128_t) d4) * r2 + (((uint128_t) r3) * (r3 * 19));
		t[2] = ((uint128_t) d0) * r2 + ((uint128_t) r1) * r1 + (((uint128_t) d4) * (r3     ));
		t[3] = ((uint128_t) d0) * r3 + ((uint128_t) d1) * r2 + (((uint128_t) r4) * (d419   ));
		t[4] = ((uint128_t) d0) * r4 + ((uint128_t) d1) * r3 + (((uint128_t) r2) * (r2     ));

				r0 = (limb)t[0] & 0x7ffffffffffffUL; c = (limb)(t[0] >> 51);
		t[1] += c;      r1 = (limb)t[1] & 0x7ffffffffffffUL; c = (limb)(t[1] >> 51);
		t[2] += c;      r2 = (limb)t[2] & 0x7ffffffffffffUL; c = (limb)(t[2] >> 51);
		t[3] += c;      r3 = (limb)t[3] & 0x7ffffffffffffUL; c = (limb)(t[3] >> 51);
		t[4] += c;      r4 = (limb)t[4] & 0x7ffffffffffffUL; c = (limb)(t[4] >> 51);
		r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffffUL;
		r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffffUL;
		r2 +=   c;
	} while (--count);

	output[0] = r0;
	output[1] = r1;
	output[2] = r2;
	output[3] = r3;
	output[4] = r4;
}

/* Load a little-endian 64-bit number  */
static limb load_limb(const uint8_t *in)
{
	return
		((limb)in[0]) |
		(((limb)in[1]) << 8) |
		(((limb)in[2]) << 16) |
		(((limb)in[3]) << 24) |
		(((limb)in[4]) << 32) |
		(((limb)in[5]) << 40) |
		(((limb)in[6]) << 48) |
		(((limb)in[7]) << 56);
}

static void store_limb(uint8_t *out, limb in)
{
	out[0] = in & 0xff;
	out[1] = (in >> 8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
	out[4] = (in >> 32) & 0xff;
	out[5] = (in >> 40) & 0xff;
	out[6] = (in >> 48) & 0xff;
	out[7] = (in >> 56) & 0xff;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void fexpand(limb *output, const uint8_t *in)
{
	output[0] = load_limb(in) & 0x7ffffffffffffUL;
	output[1] = (load_limb(in+6) >> 3) & 0x7ffffffffffffUL;
	output[2] = (load_limb(in+12) >> 6) & 0x7ffffffffffffUL;
	output[3] = (load_limb(in+19) >> 1) & 0x7ffffffffffffUL;
	output[4] = (load_limb(in+24) >> 12) & 0x7ffffffffffffUL;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void fcontract(uint8_t *output, const felem input)
{
	uint128_t t[5];

	t[0] = input[0];
	t[1] = input[1];
	t[2] = input[2];
	t[3] = input[3];
	t[4] = input[4];

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffffUL;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffffUL;

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

	t[0] += 19;

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[0] += 19 * (t[4] >> 51); t[4] &= 0x7ffffffffffffUL;

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */

	t[0] += 0x8000000000000UL - 19;
	t[1] += 0x8000000000000UL - 1;
	t[2] += 0x8000000000000UL - 1;
	t[3] += 0x8000000000000UL - 1;
	t[4] += 0x8000000000000UL - 1;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */

	t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffffUL;
	t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffffUL;
	t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffffUL;
	t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffffUL;
	t[4] &= 0x7ffffffffffffUL;

	store_limb(output,    t[0] | (t[1] << 51));
	store_limb(output+8,  (t[1] >> 13) | (t[2] << 38));
	store_limb(output+16, (t[2] >> 26) | (t[3] << 25));
	store_limb(output+24, (t[3] >> 39) | (t[4] << 12));
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 */
static void fmonty(limb *x2, limb *z2, /* output 2Q */
			 limb *x3, limb *z3, /* output Q + Q' */
			 limb *x, limb *z,   /* input Q */
			 limb *xprime, limb *zprime, /* input Q' */

			 const limb *qmqp /* input Q - Q' */)
{
	limb origx[5], origxprime[5], zzz[5], xx[5], zz[5], xxprime[5], zzprime[5], zzzprime[5];

	memcpy(origx, x, 5 * sizeof(limb));
	fsum(x, z);
	fdifference_backwards(z, origx);  // does x - z

	memcpy(origxprime, xprime, sizeof(limb) * 5);
	fsum(xprime, zprime);
	fdifference_backwards(zprime, origxprime);
	fmul(xxprime, xprime, z);
	fmul(zzprime, x, zprime);
	memcpy(origxprime, xxprime, sizeof(limb) * 5);
	fsum(xxprime, zzprime);
	fdifference_backwards(zzprime, origxprime);
	fsquare_times(x3, xxprime, 1);
	fsquare_times(zzzprime, zzprime, 1);
	fmul(z3, zzzprime, qmqp);

	fsquare_times(xx, x, 1);
	fsquare_times(zz, z, 1);
	fmul(x2, xx, zz);
	fdifference_backwards(zz, xx);  // does zz = xx - zz
	fscalar_product(zzz, zz, 121665);
	fsum(zzz, xx);
	fmul(z2, zz, zzz);
}

/* Maybe swap the contents of two limb arrays (@a and @b), each @len elements
 * long. Perform the swap iff @swap is non-zero.
 *
 * This function performs the swap without leaking any side-channel
 * information.
 */
static void swap_conditional(limb a[static 5], limb b[static 5], limb iswap)
{
	unsigned int i;
	const limb swap = -iswap;

	for (i = 0; i < 5; ++i) {
		const limb x = swap & (a[i] ^ b[i]);

		a[i] ^= x;
		b[i] ^= x;
	}
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void cmult(limb *resultx, limb *resultz, const uint8_t *n, const limb *q)
{
	limb a[5] = {0}, b[5] = {1}, c[5] = {1}, d[5] = {0};
	limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
	limb e[5] = {0}, f[5] = {1}, g[5] = {0}, h[5] = {1};
	limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

	unsigned int i, j;

	memcpy(nqpqx, q, sizeof(limb) * 5);

	for (i = 0; i < 32; ++i) {
		uint8_t byte = n[31 - i];

		for (j = 0; j < 8; ++j) {
			const limb bit = byte >> 7;

			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2,
						 nqpqx2, nqpqz2,
						 nqx, nqz,
						 nqpqx, nqpqz,
						 q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);

			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byte <<= 1;
		}
	}

	memcpy(resultx, nqx, sizeof(limb) * 5);
	memcpy(resultz, nqz, sizeof(limb) * 5);
}

static void crecip(felem out, const felem z)
{
	felem a, t0, b, c;

	/* 2 */ fsquare_times(a, z, 1); // a = 2
	/* 8 */ fsquare_times(t0, a, 2);
	/* 9 */ fmul(b, t0, z); // b = 9
	/* 11 */ fmul(a, b, a); // a = 11
	/* 22 */ fsquare_times(t0, a, 1);
	/* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
	/* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
	/* 2^10 - 2^0 */ fmul(b, t0, b);
	/* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
	/* 2^20 - 2^0 */ fmul(c, t0, b);
	/* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
	/* 2^40 - 2^0 */ fmul(t0, t0, c);
	/* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
	/* 2^50 - 2^0 */ fmul(b, t0, b);
	/* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
	/* 2^100 - 2^0 */ fmul(c, t0, b);
	/* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
	/* 2^200 - 2^0 */ fmul(t0, t0, c);
	/* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
	/* 2^250 - 2^0 */ fmul(t0, t0, b);
	/* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
	/* 2^255 - 21 */ fmul(out, t0, a);
}

void curve25519(uint8_t mypublic[static CURVE25519_POINT_SIZE], const uint8_t secret[static CURVE25519_POINT_SIZE], const uint8_t basepoint[static CURVE25519_POINT_SIZE])
{
	limb bp[5], x[5], z[5], zmone[5];
	uint8_t e[32];

	memcpy(e, secret, 32);
	curve25519_normalize_secret(e);

	fexpand(bp, basepoint);
	cmult(x, z, e, bp);
	crecip(zmone, z);
	fmul(z, x, zmone);
	fcontract(mypublic, z);
}

#else
typedef int64_t limb;

/* Field element representation:
 *
 * Field elements are written as an array of signed, 64-bit limbs, least
 * significant first. The value of the field element is:
 *   x[0] + 2^26·x[1] + x^51·x[2] + 2^102·x[3] + ...
 *
 * i.e. the limbs are 26, 25, 26, 25, ... bits wide.
 */

/* Sum two numbers: output += in */
static void fsum(limb *output, const limb *in)
{
	unsigned int i;

	for (i = 0; i < 10; i += 2) {
		output[0 + i] = output[0 + i] + in[0 + i];
		output[1 + i] = output[1 + i] + in[1 + i];
	}
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!).
 */
static void fdifference(limb *output, const limb *in)
{
	unsigned int i;

	for (i = 0; i < 10; ++i) {
		output[i] = in[i] - output[i];
	}
}

/* Multiply a number by a scalar: output = in * scalar */
static void fscalar_product(limb *output, const limb *in, const limb scalar)
{
	unsigned int i;

	for (i = 0; i < 10; ++i) {
		output[i] = in[i] * scalar;
	}
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs.
 */
static void fproduct(limb *output, const limb *in2, const limb *in)
{
	output[0] =       ((limb) ((int32_t) in2[0])) * ((int32_t) in[0]);
	output[1] =       ((limb) ((int32_t) in2[0])) * ((int32_t) in[1]) +
					    ((limb) ((int32_t) in2[1])) * ((int32_t) in[0]);
	output[2] =  2 *  ((limb) ((int32_t) in2[1])) * ((int32_t) in[1]) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[0]);
	output[3] =       ((limb) ((int32_t) in2[1])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[1]) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[3])) * ((int32_t) in[0]);
	output[4] =       ((limb) ((int32_t) in2[2])) * ((int32_t) in[2]) +
				       2 * (((limb) ((int32_t) in2[1])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[3])) * ((int32_t) in[1])) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[0]);
	output[5] =       ((limb) ((int32_t) in2[2])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[3])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in2[1])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[1]) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[5])) * ((int32_t) in[0]);
	output[6] =  2 * (((limb) ((int32_t) in2[3])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[1])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[5])) * ((int32_t) in[1])) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[0]);
	output[7] =       ((limb) ((int32_t) in2[3])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[5])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in2[1])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[1]) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[7])) * ((int32_t) in[0]);
	output[8] =       ((limb) ((int32_t) in2[4])) * ((int32_t) in[4]) +
				       2 * (((limb) ((int32_t) in2[3])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[5])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[1])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[7])) * ((int32_t) in[1])) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[0]);
	output[9] =       ((limb) ((int32_t) in2[4])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[5])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in2[3])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[7])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in2[1])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[1]) +
					    ((limb) ((int32_t) in2[0])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[0]);
	output[10] = 2 * (((limb) ((int32_t) in2[5])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[3])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[7])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[1])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[1])) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[2]);
	output[11] =      ((limb) ((int32_t) in2[5])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[7])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in2[3])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in2[2])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[2]);
	output[12] =      ((limb) ((int32_t) in2[6])) * ((int32_t) in[6]) +
				       2 * (((limb) ((int32_t) in2[5])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[7])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[3])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[3])) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[4]);
	output[13] =      ((limb) ((int32_t) in2[6])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[7])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in2[5])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in2[4])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[4]);
	output[14] = 2 * (((limb) ((int32_t) in2[7])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[5])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[5])) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[6]);
	output[15] =      ((limb) ((int32_t) in2[7])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in2[8])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in2[6])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[6]);
	output[16] =      ((limb) ((int32_t) in2[8])) * ((int32_t) in[8]) +
				       2 * (((limb) ((int32_t) in2[7])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[7]));
	output[17] =      ((limb) ((int32_t) in2[8])) * ((int32_t) in[9]) +
					    ((limb) ((int32_t) in2[9])) * ((int32_t) in[8]);
	output[18] = 2 *  ((limb) ((int32_t) in2[9])) * ((int32_t) in[9]);
}

/* Reduce a long form to a short form by taking the input mod 2^255 - 19.
 *
 * On entry: |output[i]| < 14*2^54
 * On exit: |output[0..8]| < 280*2^54
 */
static void freduce_degree(limb *output)
{
	/* Each of these shifts and adds ends up multiplying the value by 19.
	 *
	 * For output[0..8], the absolute entry value is < 14*2^54 and we add, at
	 * most, 19*14*2^54 thus, on exit, |output[0..8]| < 280*2^54.
	 */
	output[8] += output[18] << 4;
	output[8] += output[18] << 1;
	output[8] += output[18];
	output[7] += output[17] << 4;
	output[7] += output[17] << 1;
	output[7] += output[17];
	output[6] += output[16] << 4;
	output[6] += output[16] << 1;
	output[6] += output[16];
	output[5] += output[15] << 4;
	output[5] += output[15] << 1;
	output[5] += output[15];
	output[4] += output[14] << 4;
	output[4] += output[14] << 1;
	output[4] += output[14];
	output[3] += output[13] << 4;
	output[3] += output[13] << 1;
	output[3] += output[13];
	output[2] += output[12] << 4;
	output[2] += output[12] << 1;
	output[2] += output[12];
	output[1] += output[11] << 4;
	output[1] += output[11] << 1;
	output[1] += output[11];
	output[0] += output[10] << 4;
	output[0] += output[10] << 1;
	output[0] += output[10];
}

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif

/* return v / 2^26, using only shifts and adds.
 *
 * On entry: v can take any value.
 */
static inline limb div_by_2_26(const limb v)
{
	/* High word of v; no shift needed. */
	const uint32_t highword = (uint32_t) (((uint64_t) v) >> 32);
	/* Set to all 1s if v was negative; else set to 0s. */
	const int32_t sign = ((int32_t) highword) >> 31;
	/* Set to 0x3ffffff if v was negative; else set to 0. */
	const int32_t roundoff = ((uint32_t) sign) >> 6;
	/* Should return v / (1<<26) */
	return (v + roundoff) >> 26;
}

/* return v / (2^25), using only shifts and adds.
 *
 * On entry: v can take any value.
 */
static inline limb div_by_2_25(const limb v)
{
	/* High word of v; no shift needed*/
	const uint32_t highword = (uint32_t) (((uint64_t) v) >> 32);
	/* Set to all 1s if v was negative; else set to 0s. */
	const int32_t sign = ((int32_t) highword) >> 31;
	/* Set to 0x1ffffff if v was negative; else set to 0. */
	const int32_t roundoff = ((uint32_t) sign) >> 7;
	/* Should return v / (1<<25) */
	return (v + roundoff) >> 25;
}

/* Reduce all coefficients of the short form input so that |x| < 2^26.
 *
 * On entry: |output[i]| < 280*2^54
 */
static void freduce_coefficients(limb *output)
{
	unsigned int i;

	output[10] = 0;

	for (i = 0; i < 10; i += 2) {
		limb over = div_by_2_26(output[i]);
		/* The entry condition (that |output[i]| < 280*2^54) means that over is, at
		 * most, 280*2^28 in the first iteration of this loop. This is added to the
		 * next limb and we can approximate the resulting bound of that limb by
		 * 281*2^54.
		 */
		output[i] -= over << 26;
		output[i+1] += over;

		/* For the first iteration, |output[i+1]| < 281*2^54, thus |over| <
		 * 281*2^29. When this is added to the next limb, the resulting bound can
		 * be approximated as 281*2^54.
		 *
		 * For subsequent iterations of the loop, 281*2^54 remains a conservative
		 * bound and no overflow occurs.
		 */
		over = div_by_2_25(output[i+1]);
		output[i+1] -= over << 25;
		output[i+2] += over;
	}
	/* Now |output[10]| < 281*2^29 and all other coefficients are reduced. */
	output[0] += output[10] << 4;
	output[0] += output[10] << 1;
	output[0] += output[10];

	output[10] = 0;

	/* Now output[1..9] are reduced, and |output[0]| < 2^26 + 19*281*2^29
	 * So |over| will be no more than 2^16.
	 */
	{
		limb over = div_by_2_26(output[0]);

		output[0] -= over << 26;
		output[1] += over;
	}

	/* Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 2^16 < 2^26. The
	 * bound on |output[1]| is sufficient to meet our needs.
	 */
}

/* A helpful wrapper around fproduct: output = in * in2.
 *
 * On entry: |in[i]| < 2^27 and |in2[i]| < 2^27.
 *
 * output must be distinct to both inputs. The output is reduced degree
 * (indeed, one need only provide storage for 10 limbs) and |output[i]| < 2^26.
 */
static void fmul(limb *output, const limb *in, const limb *in2)
{
	limb t[19];

	fproduct(t, in, in2);
	/* |t[i]| < 14*2^54 */
	freduce_degree(t);
	freduce_coefficients(t);
	/* |t[i]| < 2^26 */
	memcpy(output, t, sizeof(limb) * 10);
}

/* Square a number: output = in**2
 *
 * output must be distinct from the input. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs.
 */
static void fsquare_inner(limb *output, const limb *in)
{
	output[0] =       ((limb) ((int32_t) in[0])) * ((int32_t) in[0]);
	output[1] =  2 *  ((limb) ((int32_t) in[0])) * ((int32_t) in[1]);
	output[2] =  2 * (((limb) ((int32_t) in[1])) * ((int32_t) in[1]) +
					    ((limb) ((int32_t) in[0])) * ((int32_t) in[2]));
	output[3] =  2 * (((limb) ((int32_t) in[1])) * ((int32_t) in[2]) +
					    ((limb) ((int32_t) in[0])) * ((int32_t) in[3]));
	output[4] =       ((limb) ((int32_t) in[2])) * ((int32_t) in[2]) +
				       4 *  ((limb) ((int32_t) in[1])) * ((int32_t) in[3]) +
				       2 *  ((limb) ((int32_t) in[0])) * ((int32_t) in[4]);
	output[5] =  2 * (((limb) ((int32_t) in[2])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in[1])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in[0])) * ((int32_t) in[5]));
	output[6] =  2 * (((limb) ((int32_t) in[3])) * ((int32_t) in[3]) +
					    ((limb) ((int32_t) in[2])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in[0])) * ((int32_t) in[6]) +
				       2 *  ((limb) ((int32_t) in[1])) * ((int32_t) in[5]));
	output[7] =  2 * (((limb) ((int32_t) in[3])) * ((int32_t) in[4]) +
					    ((limb) ((int32_t) in[2])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in[1])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in[0])) * ((int32_t) in[7]));
	output[8] =       ((limb) ((int32_t) in[4])) * ((int32_t) in[4]) +
				       2 * (((limb) ((int32_t) in[2])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in[0])) * ((int32_t) in[8]) +
				       2 * (((limb) ((int32_t) in[1])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in[3])) * ((int32_t) in[5])));
	output[9] =  2 * (((limb) ((int32_t) in[4])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in[3])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in[2])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in[1])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in[0])) * ((int32_t) in[9]));
	output[10] = 2 * (((limb) ((int32_t) in[5])) * ((int32_t) in[5]) +
					    ((limb) ((int32_t) in[4])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in[2])) * ((int32_t) in[8]) +
				       2 * (((limb) ((int32_t) in[3])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in[1])) * ((int32_t) in[9])));
	output[11] = 2 * (((limb) ((int32_t) in[5])) * ((int32_t) in[6]) +
					    ((limb) ((int32_t) in[4])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in[3])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in[2])) * ((int32_t) in[9]));
	output[12] =      ((limb) ((int32_t) in[6])) * ((int32_t) in[6]) +
				       2 * (((limb) ((int32_t) in[4])) * ((int32_t) in[8]) +
				       2 * (((limb) ((int32_t) in[5])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in[3])) * ((int32_t) in[9])));
	output[13] = 2 * (((limb) ((int32_t) in[6])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in[5])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in[4])) * ((int32_t) in[9]));
	output[14] = 2 * (((limb) ((int32_t) in[7])) * ((int32_t) in[7]) +
					    ((limb) ((int32_t) in[6])) * ((int32_t) in[8]) +
				       2 *  ((limb) ((int32_t) in[5])) * ((int32_t) in[9]));
	output[15] = 2 * (((limb) ((int32_t) in[7])) * ((int32_t) in[8]) +
					    ((limb) ((int32_t) in[6])) * ((int32_t) in[9]));
	output[16] =      ((limb) ((int32_t) in[8])) * ((int32_t) in[8]) +
				       4 *  ((limb) ((int32_t) in[7])) * ((int32_t) in[9]);
	output[17] = 2 *  ((limb) ((int32_t) in[8])) * ((int32_t) in[9]);
	output[18] = 2 *  ((limb) ((int32_t) in[9])) * ((int32_t) in[9]);
}

/* fsquare sets output = in^2.
 *
 * On entry: The |in| argument is in reduced coefficients form and |in[i]| <
 * 2^27.
 *
 * On exit: The |output| argument is in reduced coefficients form (indeed, one
 * need only provide storage for 10 limbs) and |out[i]| < 2^26.
 */
static void fsquare(limb *output, const limb *in)
{
	limb t[19];

	fsquare_inner(t, in);
	/* |t[i]| < 14*2^54 because the largest product of two limbs will be <
	 * 2^(27+27) and fsquare_inner adds together, at most, 14 of those
	 * products.
	 */
	freduce_degree(t);
	freduce_coefficients(t);
	/* |t[i]| < 2^26 */
	memcpy(output, t, sizeof(limb) * 10);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void fexpand(limb *output, const uint8_t *input)
{
#define F(n, start, shift, mask) \
	output[n] = ((((limb) input[start + 0]) | \
		      ((limb) input[start + 1]) << 8 | \
		      ((limb) input[start + 2]) << 16 | \
		      ((limb) input[start + 3]) << 24) >> shift) & mask;
	F(0, 0, 0, 0x3ffffff);
	F(1, 3, 2, 0x1ffffff);
	F(2, 6, 3, 0x3ffffff);
	F(3, 9, 5, 0x1ffffff);
	F(4, 12, 6, 0x3ffffff);
	F(5, 16, 0, 0x1ffffff);
	F(6, 19, 1, 0x3ffffff);
	F(7, 22, 3, 0x1ffffff);
	F(8, 25, 4, 0x3ffffff);
	F(9, 28, 6, 0x1ffffff);
#undef F
}

#if (-32 >> 1) != -16
#error "This code only works when >> does sign-extension on negative numbers"
#endif

/* int32_t_eq returns 0xffffffff iff a == b and zero otherwise. */
static int32_t int32_t_eq(int32_t a, int32_t b)
{
	a = ~(a ^ b);
	a &= a << 16;
	a &= a << 8;
	a &= a << 4;
	a &= a << 2;
	a &= a << 1;
	return a >> 31;
}

/* int32_t_gte returns 0xffffffff if a >= b and zero otherwise, where a and b are
 * both non-negative.
 */
static int32_t int32_t_gte(int32_t a, int32_t b)
{
	a -= b;
	/* a >= 0 iff a >= b. */
	return ~(a >> 31);
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array.
 *
 * On entry: |input_limbs[i]| < 2^26
 */
static void fcontract(uint8_t *output, limb *input_limbs)
{
	int i;
	int j;
	int32_t input[10];
	int32_t mask;

	/* |input_limbs[i]| < 2^26, so it's valid to convert to an int32_t. */
	for (i = 0; i < 10; i++) {
		input[i] = input_limbs[i];
	}

	for (j = 0; j < 2; ++j) {
		for (i = 0; i < 9; ++i) {
			if ((i & 1) == 1) {
				/* This calculation is a time-invariant way to make input[i]
				 * non-negative by borrowing from the next-larger limb.
				 */
				const int32_t mask = input[i] >> 31;
				const int32_t carry = -((input[i] & mask) >> 25);

				input[i] = input[i] + (carry << 25);
				input[i+1] = input[i+1] - carry;
			} else {
				const int32_t mask = input[i] >> 31;
				const int32_t carry = -((input[i] & mask) >> 26);

				input[i] = input[i] + (carry << 26);
				input[i+1] = input[i+1] - carry;
			}
		}

		/* There's no greater limb for input[9] to borrow from, but we can multiply
		 * by 19 and borrow from input[0], which is valid mod 2^255-19.
		 */
		{
			const int32_t mask = input[9] >> 31;
			const int32_t carry = -((input[9] & mask) >> 25);

			input[9] = input[9] + (carry << 25);
			input[0] = input[0] - (carry * 19);
		}

		/* After the first iteration, input[1..9] are non-negative and fit within
		 * 25 or 26 bits, depending on position. However, input[0] may be
		 * negative.
		 */
	}

	/* The first borrow-propagation pass above ended with every limb
		 except (possibly) input[0] non-negative.
		 If input[0] was negative after the first pass, then it was because of a
		 carry from input[9]. On entry, input[9] < 2^26 so the carry was, at most,
		 one, since (2**26-1) >> 25 = 1. Thus input[0] >= -19.
		 In the second pass, each limb is decreased by at most one. Thus the second
		 borrow-propagation pass could only have wrapped around to decrease
		 input[0] again if the first pass left input[0] negative *and* input[1]
		 through input[9] were all zero.  In that case, input[1] is now 2^25 - 1,
		 and this last borrow-propagation step will leave input[1] non-negative. */
	{
		const int32_t mask = input[0] >> 31;
		const int32_t carry = -((input[0] & mask) >> 26);

		input[0] = input[0] + (carry << 26);
		input[1] = input[1] - carry;
	}

	/* All input[i] are now non-negative. However, there might be values between
	 * 2^25 and 2^26 in a limb which is, nominally, 25 bits wide.
	 */
	for (j = 0; j < 2; j++) {
		for (i = 0; i < 9; i++) {
			if ((i & 1) == 1) {
				const int32_t carry = input[i] >> 25;

				input[i] &= 0x1ffffff;
				input[i+1] += carry;
			} else {
				const int32_t carry = input[i] >> 26;

				input[i] &= 0x3ffffff;
				input[i+1] += carry;
			}
		}

		{
			const int32_t carry = input[9] >> 25;

			input[9] &= 0x1ffffff;
			input[0] += 19*carry;
		}
	}

	/* If the first carry-chain pass, just above, ended up with a carry from
	 * input[9], and that caused input[0] to be out-of-bounds, then input[0] was
	 * < 2^26 + 2*19, because the carry was, at most, two.
	 *
	 * If the second pass carried from input[9] again then input[0] is < 2*19 and
	 * the input[9] -> input[0] carry didn't push input[0] out of bounds.
	 */

	/* It still remains the case that input might be between 2^255-19 and 2^255.
	 * In this case, input[1..9] must take their maximum value and input[0] must
	 * be >= (2^255-19) & 0x3ffffff, which is 0x3ffffed.
	 */
	mask = int32_t_gte(input[0], 0x3ffffed);
	for (i = 1; i < 10; i++) {
		if ((i & 1) == 1) {
			mask &= int32_t_eq(input[i], 0x1ffffff);
		} else {
			mask &= int32_t_eq(input[i], 0x3ffffff);
		}
	}

	/* mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus
	 * this conditionally subtracts 2^255-19.
	 */
	input[0] -= mask & 0x3ffffed;

	for (i = 1; i < 10; i++) {
		if ((i & 1) == 1) {
			input[i] -= mask & 0x1ffffff;
		} else {
			input[i] -= mask & 0x3ffffff;
		}
	}

	input[1] <<= 2;
	input[2] <<= 3;
	input[3] <<= 5;
	input[4] <<= 6;
	input[6] <<= 1;
	input[7] <<= 3;
	input[8] <<= 4;
	input[9] <<= 6;
#define F(i, s) \
	output[s+0] |=  input[i] & 0xff; \
	output[s+1]  = (input[i] >> 8) & 0xff; \
	output[s+2]  = (input[i] >> 16) & 0xff; \
	output[s+3]  = (input[i] >> 24) & 0xff;
	output[0] = 0;
	output[16] = 0;
	F(0, 0);
	F(1, 3);
	F(2, 6);
	F(3, 9);
	F(4, 12);
	F(5, 16);
	F(6, 19);
	F(7, 22);
	F(8, 25);
	F(9, 28);
#undef F
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 *
 * On entry and exit, the absolute value of the limbs of all inputs and outputs
 * are < 2^26.
 */
static void fmonty(limb *x2, limb *z2,  /* output 2Q */
		   limb *x3, limb *z3,  /* output Q + Q' */
		   limb *x, limb *z,    /* input Q */
		   limb *xprime, limb *zprime,  /* input Q' */

		   const limb *qmqp /* input Q - Q' */)
{
	limb origx[10], origxprime[10], zzz[19], xx[19], zz[19], xxprime[19],
				zzprime[19], zzzprime[19], xxxprime[19];

	memcpy(origx, x, 10 * sizeof(limb));
	fsum(x, z);
	/* |x[i]| < 2^27 */
	fdifference(z, origx);  /* does x - z */
	/* |z[i]| < 2^27 */

	memcpy(origxprime, xprime, sizeof(limb) * 10);
	fsum(xprime, zprime);
	/* |xprime[i]| < 2^27 */
	fdifference(zprime, origxprime);
	/* |zprime[i]| < 2^27 */
	fproduct(xxprime, xprime, z);
	/* |xxprime[i]| < 14*2^54: the largest product of two limbs will be <
	 * 2^(27+27) and fproduct adds together, at most, 14 of those products.
	 * (Approximating that to 2^58 doesn't work out.)
	 */
	fproduct(zzprime, x, zprime);
	/* |zzprime[i]| < 14*2^54 */
	freduce_degree(xxprime);
	freduce_coefficients(xxprime);
	/* |xxprime[i]| < 2^26 */
	freduce_degree(zzprime);
	freduce_coefficients(zzprime);
	/* |zzprime[i]| < 2^26 */
	memcpy(origxprime, xxprime, sizeof(limb) * 10);
	fsum(xxprime, zzprime);
	/* |xxprime[i]| < 2^27 */
	fdifference(zzprime, origxprime);
	/* |zzprime[i]| < 2^27 */
	fsquare(xxxprime, xxprime);
	/* |xxxprime[i]| < 2^26 */
	fsquare(zzzprime, zzprime);
	/* |zzzprime[i]| < 2^26 */
	fproduct(zzprime, zzzprime, qmqp);
	/* |zzprime[i]| < 14*2^52 */
	freduce_degree(zzprime);
	freduce_coefficients(zzprime);
	/* |zzprime[i]| < 2^26 */
	memcpy(x3, xxxprime, sizeof(limb) * 10);
	memcpy(z3, zzprime, sizeof(limb) * 10);

	fsquare(xx, x);
	/* |xx[i]| < 2^26 */
	fsquare(zz, z);
	/* |zz[i]| < 2^26 */
	fproduct(x2, xx, zz);
	/* |x2[i]| < 14*2^52 */
	freduce_degree(x2);
	freduce_coefficients(x2);
	/* |x2[i]| < 2^26 */
	fdifference(zz, xx);  // does zz = xx - zz
	/* |zz[i]| < 2^27 */
	memset(zzz + 10, 0, sizeof(limb) * 9);
	fscalar_product(zzz, zz, 121665);
	/* |zzz[i]| < 2^(27+17) */
	/* No need to call freduce_degree here:
		 fscalar_product doesn't increase the degree of its input. */
	freduce_coefficients(zzz);
	/* |zzz[i]| < 2^26 */
	fsum(zzz, xx);
	/* |zzz[i]| < 2^27 */
	fproduct(z2, zz, zzz);
	/* |z2[i]| < 14*2^(26+27) */
	freduce_degree(z2);
	freduce_coefficients(z2);
	/* |z2|i| < 2^26 */
}

/* Conditionally swap two reduced-form limb arrays if 'iswap' is 1, but leave
 * them unchanged if 'iswap' is 0.  Runs in data-invariant time to avoid
 * side-channel attacks.
 *
 * NOTE that this function requires that 'iswap' be 1 or 0; other values give
 * wrong results.  Also, the two limb arrays must be in reduced-coefficient,
 * reduced-degree form: the values in a[10..19] or b[10..19] aren't swapped,
 * and all all values in a[0..9],b[0..9] must have magnitude less than
 * INT32_MAX.
 */
static void swap_conditional(limb a[static 19], limb b[static 19], limb iswap)
{
	unsigned int i;
	const int32_t swap = (int32_t) -iswap;

	for (i = 0; i < 10; ++i) {
		const int32_t x = swap & (((int32_t)a[i]) ^ ((int32_t)b[i]));

		a[i] = ((int32_t)a[i]) ^ x;
		b[i] = ((int32_t)b[i]) ^ x;
	}
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void cmult(limb *resultx, limb *resultz, const uint8_t *n, const limb *q)
{
	limb a[19] = {0}, b[19] = {1}, c[19] = {1}, d[19] = {0};
	limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
	limb e[19] = {0}, f[19] = {1}, g[19] = {0}, h[19] = {1};
	limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

	unsigned int i, j;

	memcpy(nqpqx, q, sizeof(limb) * 10);

	for (i = 0; i < 32; ++i) {
		uint8_t byte = n[31 - i];

		for (j = 0; j < 8; ++j) {
			const limb bit = byte >> 7;

			swap_conditional(nqx, nqpqx, bit);
			swap_conditional(nqz, nqpqz, bit);
			fmonty(nqx2, nqz2,
			       nqpqx2, nqpqz2,
			       nqx, nqz,
			       nqpqx, nqpqz,
			       q);
			swap_conditional(nqx2, nqpqx2, bit);
			swap_conditional(nqz2, nqpqz2, bit);

			t = nqx;
			nqx = nqx2;
			nqx2 = t;
			t = nqz;
			nqz = nqz2;
			nqz2 = t;
			t = nqpqx;
			nqpqx = nqpqx2;
			nqpqx2 = t;
			t = nqpqz;
			nqpqz = nqpqz2;
			nqpqz2 = t;

			byte <<= 1;
		}
	}

	memcpy(resultx, nqx, sizeof(limb) * 10);
	memcpy(resultz, nqz, sizeof(limb) * 10);
}

static void crecip(limb *out, const limb *z)
{
	limb z2[10];
	limb z9[10];
	limb z11[10];
	limb z2_5_0[10];
	limb z2_10_0[10];
	limb z2_20_0[10];
	limb z2_50_0[10];
	limb z2_100_0[10];
	limb t0[10];
	limb t1[10];
	int i;

	/* 2 */ fsquare(z2, z);
	/* 4 */ fsquare(t1, z2);
	/* 8 */ fsquare(t0, t1);
	/* 9 */ fmul(z9, t0, z);
	/* 11 */ fmul(z11, z9, z2);
	/* 22 */ fsquare(t0, z11);
	/* 2^5 - 2^0 = 31 */ fmul(z2_5_0, t0, z9);

	/* 2^6 - 2^1 */ fsquare(t0, z2_5_0);
	/* 2^7 - 2^2 */ fsquare(t1, t0);
	/* 2^8 - 2^3 */ fsquare(t0, t1);
	/* 2^9 - 2^4 */ fsquare(t1, t0);
	/* 2^10 - 2^5 */ fsquare(t0, t1);
	/* 2^10 - 2^0 */ fmul(z2_10_0, t0, z2_5_0);

	/* 2^11 - 2^1 */ fsquare(t0, z2_10_0);
	/* 2^12 - 2^2 */ fsquare(t1, t0);
	/* 2^20 - 2^10 */ for (i = 2; i < 10; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^20 - 2^0 */ fmul(z2_20_0, t1, z2_10_0);

	/* 2^21 - 2^1 */ fsquare(t0, z2_20_0);
	/* 2^22 - 2^2 */ fsquare(t1, t0);
	/* 2^40 - 2^20 */ for (i = 2; i < 20; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^40 - 2^0 */ fmul(t0, t1, z2_20_0);

	/* 2^41 - 2^1 */ fsquare(t1, t0);
	/* 2^42 - 2^2 */ fsquare(t0, t1);
	/* 2^50 - 2^10 */ for (i = 2; i < 10; i += 2) { fsquare(t1, t0); fsquare(t0, t1); }
	/* 2^50 - 2^0 */ fmul(z2_50_0, t0, z2_10_0);

	/* 2^51 - 2^1 */ fsquare(t0, z2_50_0);
	/* 2^52 - 2^2 */ fsquare(t1, t0);
	/* 2^100 - 2^50 */ for (i = 2; i < 50; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^100 - 2^0 */ fmul(z2_100_0, t1, z2_50_0);

	/* 2^101 - 2^1 */ fsquare(t1, z2_100_0);
	/* 2^102 - 2^2 */ fsquare(t0, t1);
	/* 2^200 - 2^100 */ for (i = 2; i < 100; i += 2) { fsquare(t1, t0); fsquare(t0, t1); }
	/* 2^200 - 2^0 */ fmul(t1, t0, z2_100_0);

	/* 2^201 - 2^1 */ fsquare(t0, t1);
	/* 2^202 - 2^2 */ fsquare(t1, t0);
	/* 2^250 - 2^50 */ for (i = 2; i < 50; i += 2) { fsquare(t0, t1); fsquare(t1, t0); }
	/* 2^250 - 2^0 */ fmul(t0, t1, z2_50_0);

	/* 2^251 - 2^1 */ fsquare(t1, t0);
	/* 2^252 - 2^2 */ fsquare(t0, t1);
	/* 2^253 - 2^3 */ fsquare(t1, t0);
	/* 2^254 - 2^4 */ fsquare(t0, t1);
	/* 2^255 - 2^5 */ fsquare(t1, t0);
	/* 2^255 - 21 */ fmul(out, t1, z11);
}

void curve25519(uint8_t mypublic[static CURVE25519_POINT_SIZE], const uint8_t secret[static CURVE25519_POINT_SIZE], const uint8_t basepoint[static CURVE25519_POINT_SIZE])
{
	limb bp[10], x[10], z[11], zmone[10];
	uint8_t e[32];

	memcpy(e, secret, 32);
	curve25519_normalize_secret(e);

	fexpand(bp, basepoint);
	cmult(x, z, e, bp);
	crecip(zmone, z);
	fmul(z, x, zmone);
	fcontract(mypublic, z);
}
#endif

void curve25519_generate_public(uint8_t pub[static CURVE25519_POINT_SIZE], const uint8_t secret[static CURVE25519_POINT_SIZE])
{
	static const uint8_t basepoint[CURVE25519_POINT_SIZE] = { 9 };

	curve25519(pub, secret, basepoint);
}
