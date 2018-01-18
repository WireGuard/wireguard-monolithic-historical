/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2017 INRIA and Microsoft Corporation.
 * Copyright (C) 2015-2016 The fiat-crypto Authors.
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is a machine-generated formally verified implementation of curve25519 DH from:
 * https://github.com/mitls/hacl-star and https://github.com/mit-plv/fiat-crypto
 */

#include "curve25519.h"

#include <stdint.h>
#include <string.h>
#include <endian.h>

#ifndef __always_inline
#define __always_inline __inline __attribute__((__always_inline__))
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif

#ifdef __SIZEOF_INT128__
typedef __uint128_t uint128_t;

static __always_inline uint64_t uint64_t_eq_mask(uint64_t x, uint64_t y)
{
	x = ~(x ^ y);
	x &= x << 32;
	x &= x << 16;
	x &= x << 8;
	x &= x << 4;
	x &= x << 2;
	x &= x << 1;
	return ((int64_t)x) >> 63;
}

static __always_inline uint64_t uint64_t_gte_mask(uint64_t x, uint64_t y)
{
	uint64_t low63 = ~((uint64_t)((int64_t)((int64_t)(x & 0x7fffffffffffffffLLU) - (int64_t)(y & 0x7fffffffffffffffLLU)) >> 63));
	uint64_t high_bit = ~((uint64_t)((int64_t)((int64_t)(x & 0x8000000000000000LLU) - (int64_t)(y & 0x8000000000000000LLU)) >> 63));
	return low63 & high_bit;
}

static __always_inline void modulo_carry_top(uint64_t *b)
{
	uint64_t b4 = b[4];
	uint64_t b0 = b[0];
	uint64_t b4_ = b4 & 0x7ffffffffffffLLU;
	uint64_t b0_ = b0 + 19 * (b4 >> 51);
	b[4] = b4_;
	b[0] = b0_;
}

static __always_inline void fproduct_copy_from_wide_(uint64_t *output, uint128_t *input)
{
	{
		uint128_t xi = input[0];
		output[0] = ((uint64_t)(xi));
	}
	{
		uint128_t xi = input[1];
		output[1] = ((uint64_t)(xi));
	}
	{
		uint128_t xi = input[2];
		output[2] = ((uint64_t)(xi));
	}
	{
		uint128_t xi = input[3];
		output[3] = ((uint64_t)(xi));
	}
	{
		uint128_t xi = input[4];
		output[4] = ((uint64_t)(xi));
	}
}

static __always_inline void fproduct_sum_scalar_multiplication_(uint128_t *output, uint64_t *input, uint64_t s)
{
	uint32_t i;
	for (i = 0; i < 5; ++i) {
		uint128_t xi = output[i];
		uint64_t yi = input[i];
		output[i] = ((xi) + (((uint128_t)(yi) * (s))));
	}
}

static __always_inline void fproduct_carry_wide_(uint128_t *tmp)
{
	uint32_t i;
	for (i = 0; i < 4; ++i) {
		uint32_t ctr = i;
		uint128_t tctr = tmp[ctr];
		uint128_t tctrp1 = tmp[ctr + 1];
		uint64_t r0 = ((uint64_t)(tctr)) & 0x7ffffffffffffLLU;
		uint128_t c = ((tctr) >> (51));
		tmp[ctr] = ((uint128_t)(r0));
		tmp[ctr + 1] = ((tctrp1) + (c));
	}
}

static __always_inline void fmul_shift_reduce(uint64_t *output)
{
	uint64_t tmp = output[4];
	uint64_t b0;
	{
		uint32_t ctr = 5 - 0 - 1;
		uint64_t z = output[ctr - 1];
		output[ctr] = z;
	}
	{
		uint32_t ctr = 5 - 1 - 1;
		uint64_t z = output[ctr - 1];
		output[ctr] = z;
	}
	{
		uint32_t ctr = 5 - 2 - 1;
		uint64_t z = output[ctr - 1];
		output[ctr] = z;
	}
	{
		uint32_t ctr = 5 - 3 - 1;
		uint64_t z = output[ctr - 1];
		output[ctr] = z;
	}
	output[0] = tmp;
	b0 = output[0];
	output[0] = 19 * b0;
}

static __always_inline void fmul_mul_shift_reduce_(uint128_t *output, uint64_t *input, uint64_t *input21)
{
	uint32_t i;
	uint64_t input2i;
	{
		uint64_t input2i = input21[0];
		fproduct_sum_scalar_multiplication_(output, input, input2i);
		fmul_shift_reduce(input);
	}
	{
		uint64_t input2i = input21[1];
		fproduct_sum_scalar_multiplication_(output, input, input2i);
		fmul_shift_reduce(input);
	}
	{
		uint64_t input2i = input21[2];
		fproduct_sum_scalar_multiplication_(output, input, input2i);
		fmul_shift_reduce(input);
	}
	{
		uint64_t input2i = input21[3];
		fproduct_sum_scalar_multiplication_(output, input, input2i);
		fmul_shift_reduce(input);
	}
	i = 4;
	input2i = input21[i];
	fproduct_sum_scalar_multiplication_(output, input, input2i);
}

static __always_inline void fmul_fmul(uint64_t *output, uint64_t *input, uint64_t *input21)
{
	uint64_t tmp[5];
	memcpy(tmp, input, 5 * sizeof(*input));
	{
		uint128_t b4;
		uint128_t b0;
		uint128_t b4_;
		uint128_t b0_;
		uint64_t i0;
		uint64_t i1;
		uint64_t i0_;
		uint64_t i1_;
		uint128_t t[5];
		{
			uint32_t _i;
			for (_i = 0; _i < 5; ++_i)
				t[_i] = ((uint128_t)(0));
		}
		fmul_mul_shift_reduce_(t, tmp, input21);
		fproduct_carry_wide_(t);
		b4 = t[4];
		b0 = t[0];
		b4_ = ((b4) & (((uint128_t)(0x7ffffffffffffLLU))));
		b0_ = ((b0) + (((uint128_t)(19) * (((uint64_t)(((b4) >> (51))))))));
		t[4] = b4_;
		t[0] = b0_;
		fproduct_copy_from_wide_(output, t);
		i0 = output[0];
		i1 = output[1];
		i0_ = i0 & 0x7ffffffffffffLLU;
		i1_ = i1 + (i0 >> 51);
		output[0] = i0_;
		output[1] = i1_;
	}
}

static __always_inline void fsquare_fsquare__(uint128_t *tmp, uint64_t *output)
{
	uint64_t r0 = output[0];
	uint64_t r1 = output[1];
	uint64_t r2 = output[2];
	uint64_t r3 = output[3];
	uint64_t r4 = output[4];
	uint64_t d0 = r0 * 2;
	uint64_t d1 = r1 * 2;
	uint64_t d2 = r2 * 2 * 19;
	uint64_t d419 = r4 * 19;
	uint64_t d4 = d419 * 2;
	uint128_t s0 = ((((((uint128_t)(r0) * (r0))) + (((uint128_t)(d4) * (r1))))) + (((uint128_t)(d2) * (r3))));
	uint128_t s1 = ((((((uint128_t)(d0) * (r1))) + (((uint128_t)(d4) * (r2))))) + (((uint128_t)(r3 * 19) * (r3))));
	uint128_t s2 = ((((((uint128_t)(d0) * (r2))) + (((uint128_t)(r1) * (r1))))) + (((uint128_t)(d4) * (r3))));
	uint128_t s3 = ((((((uint128_t)(d0) * (r3))) + (((uint128_t)(d1) * (r2))))) + (((uint128_t)(r4) * (d419))));
	uint128_t s4 = ((((((uint128_t)(d0) * (r4))) + (((uint128_t)(d1) * (r3))))) + (((uint128_t)(r2) * (r2))));
	tmp[0] = s0;
	tmp[1] = s1;
	tmp[2] = s2;
	tmp[3] = s3;
	tmp[4] = s4;
}

static __always_inline void fsquare_fsquare_(uint128_t *tmp, uint64_t *output)
{
	uint128_t b4;
	uint128_t b0;
	uint128_t b4_;
	uint128_t b0_;
	uint64_t i0;
	uint64_t i1;
	uint64_t i0_;
	uint64_t i1_;
	fsquare_fsquare__(tmp, output);
	fproduct_carry_wide_(tmp);
	b4 = tmp[4];
	b0 = tmp[0];
	b4_ = ((b4) & (((uint128_t)(0x7ffffffffffffLLU))));
	b0_ = ((b0) + (((uint128_t)(19) * (((uint64_t)(((b4) >> (51))))))));
	tmp[4] = b4_;
	tmp[0] = b0_;
	fproduct_copy_from_wide_(output, tmp);
	i0 = output[0];
	i1 = output[1];
	i0_ = i0 & 0x7ffffffffffffLLU;
	i1_ = i1 + (i0 >> 51);
	output[0] = i0_;
	output[1] = i1_;
}

static __always_inline void fsquare_fsquare_times_(uint64_t *input, uint128_t *tmp, uint32_t count1)
{
	uint32_t i;
	fsquare_fsquare_(tmp, input);
	for (i = 1; i < count1; ++i)
		fsquare_fsquare_(tmp, input);
}

static __always_inline void fsquare_fsquare_times(uint64_t *output, uint64_t *input, uint32_t count1)
{
	uint128_t t[5];
	{
		uint32_t _i;
		for (_i = 0; _i < 5; ++_i)
			t[_i] = ((uint128_t)(0));
	}
	memcpy(output, input, 5 * sizeof(*input));
	fsquare_fsquare_times_(output, t, count1);
}

static __always_inline void fsquare_fsquare_times_inplace(uint64_t *output, uint32_t count1)
{
	uint128_t t[5];
	{
		uint32_t _i;
		for (_i = 0; _i < 5; ++_i)
			t[_i] = ((uint128_t)(0));
	}
	fsquare_fsquare_times_(output, t, count1);
}

static __always_inline void crecip_crecip(uint64_t *out, uint64_t *z)
{
	uint64_t buf[20] = { 0 };
	uint64_t *a0 = buf;
	uint64_t *t00 = buf + 5;
	uint64_t *b0 = buf + 10;
	uint64_t *t01;
	uint64_t *b1;
	uint64_t *c0;
	uint64_t *a;
	uint64_t *t0;
	uint64_t *b;
	uint64_t *c;
	fsquare_fsquare_times(a0, z, 1);
	fsquare_fsquare_times(t00, a0, 2);
	fmul_fmul(b0, t00, z);
	fmul_fmul(a0, b0, a0);
	fsquare_fsquare_times(t00, a0, 1);
	fmul_fmul(b0, t00, b0);
	fsquare_fsquare_times(t00, b0, 5);
	t01 = buf + 5;
	b1 = buf + 10;
	c0 = buf + 15;
	fmul_fmul(b1, t01, b1);
	fsquare_fsquare_times(t01, b1, 10);
	fmul_fmul(c0, t01, b1);
	fsquare_fsquare_times(t01, c0, 20);
	fmul_fmul(t01, t01, c0);
	fsquare_fsquare_times_inplace(t01, 10);
	fmul_fmul(b1, t01, b1);
	fsquare_fsquare_times(t01, b1, 50);
	a = buf;
	t0 = buf + 5;
	b = buf + 10;
	c = buf + 15;
	fmul_fmul(c, t0, b);
	fsquare_fsquare_times(t0, c, 100);
	fmul_fmul(t0, t0, c);
	fsquare_fsquare_times_inplace(t0, 50);
	fmul_fmul(t0, t0, b);
	fsquare_fsquare_times_inplace(t0, 5);
	fmul_fmul(out, t0, a);
}

static __always_inline void fsum(uint64_t *a, uint64_t *b)
{
	uint32_t i;
	for (i = 0; i < 5; ++i) {
		uint64_t xi = a[i];
		uint64_t yi = b[i];
		a[i] = xi + yi;
	}
}

static __always_inline void fdifference(uint64_t *a, uint64_t *b)
{
	uint64_t tmp[5] = { 0 };
	uint64_t b0;
	uint64_t b1;
	uint64_t b2;
	uint64_t b3;
	uint64_t b4;
	memcpy(tmp, b, 5 * sizeof(*b));
	b0 = tmp[0];
	b1 = tmp[1];
	b2 = tmp[2];
	b3 = tmp[3];
	b4 = tmp[4];
	tmp[0] = b0 + 0x3fffffffffff68LLU;
	tmp[1] = b1 + 0x3ffffffffffff8LLU;
	tmp[2] = b2 + 0x3ffffffffffff8LLU;
	tmp[3] = b3 + 0x3ffffffffffff8LLU;
	tmp[4] = b4 + 0x3ffffffffffff8LLU;
	{
		uint64_t xi = a[0];
		uint64_t yi = tmp[0];
		a[0] = yi - xi;
	}
	{
		uint64_t xi = a[1];
		uint64_t yi = tmp[1];
		a[1] = yi - xi;
	}
	{
		uint64_t xi = a[2];
		uint64_t yi = tmp[2];
		a[2] = yi - xi;
	}
	{
		uint64_t xi = a[3];
		uint64_t yi = tmp[3];
		a[3] = yi - xi;
	}
	{
		uint64_t xi = a[4];
		uint64_t yi = tmp[4];
		a[4] = yi - xi;
	}
}

static __always_inline void fscalar(uint64_t *output, uint64_t *b, uint64_t s)
{
	uint128_t tmp[5];
	uint128_t b4;
	uint128_t b0;
	uint128_t b4_;
	uint128_t b0_;
	{
		uint64_t xi = b[0];
		tmp[0] = ((uint128_t)(xi) * (s));
	}
	{
		uint64_t xi = b[1];
		tmp[1] = ((uint128_t)(xi) * (s));
	}
	{
		uint64_t xi = b[2];
		tmp[2] = ((uint128_t)(xi) * (s));
	}
	{
		uint64_t xi = b[3];
		tmp[3] = ((uint128_t)(xi) * (s));
	}
	{
		uint64_t xi = b[4];
		tmp[4] = ((uint128_t)(xi) * (s));
	}
	fproduct_carry_wide_(tmp);
	b4 = tmp[4];
	b0 = tmp[0];
	b4_ = ((b4) & (((uint128_t)(0x7ffffffffffffLLU))));
	b0_ = ((b0) + (((uint128_t)(19) * (((uint64_t)(((b4) >> (51))))))));
	tmp[4] = b4_;
	tmp[0] = b0_;
	fproduct_copy_from_wide_(output, tmp);
}

static __always_inline void fmul(uint64_t *output, uint64_t *a, uint64_t *b)
{
	fmul_fmul(output, a, b);
}

static __always_inline void crecip(uint64_t *output, uint64_t *input)
{
	crecip_crecip(output, input);
}

static __always_inline void point_swap_conditional_step(uint64_t *a, uint64_t *b, uint64_t swap1, uint32_t ctr)
{
	uint32_t i = ctr - 1;
	uint64_t ai = a[i];
	uint64_t bi = b[i];
	uint64_t x = swap1 & (ai ^ bi);
	uint64_t ai1 = ai ^ x;
	uint64_t bi1 = bi ^ x;
	a[i] = ai1;
	b[i] = bi1;
}

static __always_inline void point_swap_conditional_(uint64_t *a, uint64_t *b, uint64_t swap1, uint32_t ctr)
{
	uint32_t i;
	for (i = ctr; i > 0; --i)
		point_swap_conditional_step(a, b, swap1, i);
}

static __always_inline void point_swap_conditional(uint64_t *a, uint64_t *b, uint64_t iswap)
{
	uint64_t swap1 = 0 - iswap;
	point_swap_conditional_(a, b, swap1, 5);
	point_swap_conditional_(a + 5, b + 5, swap1, 5);
}

static __always_inline void point_copy(uint64_t *output, uint64_t *input)
{
	memcpy(output, input, 5 * sizeof(*input));
	memcpy(output + 5, input + 5, 5 * sizeof(*input));
}

static __always_inline void addanddouble_fmonty(uint64_t *pp, uint64_t *ppq, uint64_t *p, uint64_t *pq, uint64_t *qmqp)
{
	uint64_t *qx = qmqp;
	uint64_t *x2 = pp;
	uint64_t *z2 = pp + 5;
	uint64_t *x3 = ppq;
	uint64_t *z3 = ppq + 5;
	uint64_t *x = p;
	uint64_t *z = p + 5;
	uint64_t *xprime = pq;
	uint64_t *zprime = pq + 5;
	uint64_t buf[40] = { 0 };
	uint64_t *origx = buf;
	uint64_t *origxprime0 = buf + 5;
	uint64_t *xxprime0;
	uint64_t *zzprime0;
	uint64_t *origxprime;
	xxprime0 = buf + 25;
	zzprime0 = buf + 30;
	memcpy(origx, x, 5 * sizeof(*x));
	fsum(x, z);
	fdifference(z, origx);
	memcpy(origxprime0, xprime, 5 * sizeof(*xprime));
	fsum(xprime, zprime);
	fdifference(zprime, origxprime0);
	fmul(xxprime0, xprime, z);
	fmul(zzprime0, x, zprime);
	origxprime = buf + 5;
	{
		uint64_t *xx0;
		uint64_t *zz0;
		uint64_t *xxprime;
		uint64_t *zzprime;
		uint64_t *zzzprime;
		xx0 = buf + 15;
		zz0 = buf + 20;
		xxprime = buf + 25;
		zzprime = buf + 30;
		zzzprime = buf + 35;
		memcpy(origxprime, xxprime, 5 * sizeof(*xxprime));
		fsum(xxprime, zzprime);
		fdifference(zzprime, origxprime);
		fsquare_fsquare_times(x3, xxprime, 1);
		fsquare_fsquare_times(zzzprime, zzprime, 1);
		fmul(z3, zzzprime, qx);
		fsquare_fsquare_times(xx0, x, 1);
		fsquare_fsquare_times(zz0, z, 1);
		{
			uint64_t *zzz;
			uint64_t *xx;
			uint64_t *zz;
			uint64_t scalar;
			zzz = buf + 10;
			xx = buf + 15;
			zz = buf + 20;
			fmul(x2, xx, zz);
			fdifference(zz, xx);
			scalar = 121665;
			fscalar(zzz, zz, scalar);
			fsum(zzz, xx);
			fmul(z2, zzz, zz);
		}
	}
}

static __always_inline void ladder_smallloop_cmult_small_loop_step(uint64_t *nq, uint64_t *nqpq, uint64_t *nq2, uint64_t *nqpq2, uint64_t *q, uint8_t byt)
{
	uint64_t bit0 = (uint64_t)(byt >> 7);
	uint64_t bit;
	point_swap_conditional(nq, nqpq, bit0);
	addanddouble_fmonty(nq2, nqpq2, nq, nqpq, q);
	bit = (uint64_t)(byt >> 7);
	point_swap_conditional(nq2, nqpq2, bit);
}

static __always_inline void ladder_smallloop_cmult_small_loop_double_step(uint64_t *nq, uint64_t *nqpq, uint64_t *nq2, uint64_t *nqpq2, uint64_t *q, uint8_t byt)
{
	uint8_t byt1;
	ladder_smallloop_cmult_small_loop_step(nq, nqpq, nq2, nqpq2, q, byt);
	byt1 = byt << 1;
	ladder_smallloop_cmult_small_loop_step(nq2, nqpq2, nq, nqpq, q, byt1);
}

static __always_inline void ladder_smallloop_cmult_small_loop(uint64_t *nq, uint64_t *nqpq, uint64_t *nq2, uint64_t *nqpq2, uint64_t *q, uint8_t byt, uint32_t i)
{
	while (i--) {
		ladder_smallloop_cmult_small_loop_double_step(nq, nqpq, nq2, nqpq2, q, byt);
		byt <<= 2;
	}
}

static __always_inline void ladder_bigloop_cmult_big_loop(uint8_t *n1, uint64_t *nq, uint64_t *nqpq, uint64_t *nq2, uint64_t *nqpq2, uint64_t *q, uint32_t i)
{
	while (i--) {
		uint8_t byte = n1[i];
		ladder_smallloop_cmult_small_loop(nq, nqpq, nq2, nqpq2, q, byte, 4);
	}
}

static __always_inline void ladder_cmult(uint64_t *result, uint8_t *n1, uint64_t *q)
{
	uint64_t point_buf[40] = { 0 };
	uint64_t *nq = point_buf;
	uint64_t *nqpq = point_buf + 10;
	uint64_t *nq2 = point_buf + 20;
	uint64_t *nqpq2 = point_buf + 30;
	point_copy(nqpq, q);
	nq[0] = 1;
	ladder_bigloop_cmult_big_loop(n1, nq, nqpq, nq2, nqpq2, q, 32);
	point_copy(result, nq);
}

static __always_inline void format_fexpand(uint64_t *output, const uint8_t *input)
{
	const uint8_t *x00 = input + 6;
	const uint8_t *x01 = input + 12;
	const uint8_t *x02 = input + 19;
	const uint8_t *x0 = input + 24;
	uint64_t i0, i1, i2, i3, i4, output0, output1, output2, output3, output4;
	i0 = le64toh(*(uint64_t *)input);
	i1 = le64toh(*(uint64_t *)x00);
	i2 = le64toh(*(uint64_t *)x01);
	i3 = le64toh(*(uint64_t *)x02);
	i4 = le64toh(*(uint64_t *)x0);
	output0 = i0 & 0x7ffffffffffffLLU;
	output1 = i1 >> 3 & 0x7ffffffffffffLLU;
	output2 = i2 >> 6 & 0x7ffffffffffffLLU;
	output3 = i3 >> 1 & 0x7ffffffffffffLLU;
	output4 = i4 >> 12 & 0x7ffffffffffffLLU;
	output[0] = output0;
	output[1] = output1;
	output[2] = output2;
	output[3] = output3;
	output[4] = output4;
}

static __always_inline void format_fcontract_first_carry_pass(uint64_t *input)
{
	uint64_t t0 = input[0];
	uint64_t t1 = input[1];
	uint64_t t2 = input[2];
	uint64_t t3 = input[3];
	uint64_t t4 = input[4];
	uint64_t t1_ = t1 + (t0 >> 51);
	uint64_t t0_ = t0 & 0x7ffffffffffffLLU;
	uint64_t t2_ = t2 + (t1_ >> 51);
	uint64_t t1__ = t1_ & 0x7ffffffffffffLLU;
	uint64_t t3_ = t3 + (t2_ >> 51);
	uint64_t t2__ = t2_ & 0x7ffffffffffffLLU;
	uint64_t t4_ = t4 + (t3_ >> 51);
	uint64_t t3__ = t3_ & 0x7ffffffffffffLLU;
	input[0] = t0_;
	input[1] = t1__;
	input[2] = t2__;
	input[3] = t3__;
	input[4] = t4_;
}

static __always_inline void format_fcontract_first_carry_full(uint64_t *input)
{
	format_fcontract_first_carry_pass(input);
	modulo_carry_top(input);
}

static __always_inline void format_fcontract_second_carry_pass(uint64_t *input)
{
	uint64_t t0 = input[0];
	uint64_t t1 = input[1];
	uint64_t t2 = input[2];
	uint64_t t3 = input[3];
	uint64_t t4 = input[4];
	uint64_t t1_ = t1 + (t0 >> 51);
	uint64_t t0_ = t0 & 0x7ffffffffffffLLU;
	uint64_t t2_ = t2 + (t1_ >> 51);
	uint64_t t1__ = t1_ & 0x7ffffffffffffLLU;
	uint64_t t3_ = t3 + (t2_ >> 51);
	uint64_t t2__ = t2_ & 0x7ffffffffffffLLU;
	uint64_t t4_ = t4 + (t3_ >> 51);
	uint64_t t3__ = t3_ & 0x7ffffffffffffLLU;
	input[0] = t0_;
	input[1] = t1__;
	input[2] = t2__;
	input[3] = t3__;
	input[4] = t4_;
}

static __always_inline void format_fcontract_second_carry_full(uint64_t *input)
{
	uint64_t i0;
	uint64_t i1;
	uint64_t i0_;
	uint64_t i1_;
	format_fcontract_second_carry_pass(input);
	modulo_carry_top(input);
	i0 = input[0];
	i1 = input[1];
	i0_ = i0 & 0x7ffffffffffffLLU;
	i1_ = i1 + (i0 >> 51);
	input[0] = i0_;
	input[1] = i1_;
}

static __always_inline void format_fcontract_trim(uint64_t *input)
{
	uint64_t a0 = input[0];
	uint64_t a1 = input[1];
	uint64_t a2 = input[2];
	uint64_t a3 = input[3];
	uint64_t a4 = input[4];
	uint64_t mask0 = uint64_t_gte_mask(a0, 0x7ffffffffffedLLU);
	uint64_t mask1 = uint64_t_eq_mask(a1, 0x7ffffffffffffLLU);
	uint64_t mask2 = uint64_t_eq_mask(a2, 0x7ffffffffffffLLU);
	uint64_t mask3 = uint64_t_eq_mask(a3, 0x7ffffffffffffLLU);
	uint64_t mask4 = uint64_t_eq_mask(a4, 0x7ffffffffffffLLU);
	uint64_t mask = (((mask0 & mask1) & mask2) & mask3) & mask4;
	uint64_t a0_ = a0 - (0x7ffffffffffedLLU & mask);
	uint64_t a1_ = a1 - (0x7ffffffffffffLLU & mask);
	uint64_t a2_ = a2 - (0x7ffffffffffffLLU & mask);
	uint64_t a3_ = a3 - (0x7ffffffffffffLLU & mask);
	uint64_t a4_ = a4 - (0x7ffffffffffffLLU & mask);
	input[0] = a0_;
	input[1] = a1_;
	input[2] = a2_;
	input[3] = a3_;
	input[4] = a4_;
}

static __always_inline void format_fcontract_store(uint8_t *output, uint64_t *input)
{
	uint64_t t0 = input[0];
	uint64_t t1 = input[1];
	uint64_t t2 = input[2];
	uint64_t t3 = input[3];
	uint64_t t4 = input[4];
	uint64_t o0 = t1 << 51 | t0;
	uint64_t o1 = t2 << 38 | t1 >> 13;
	uint64_t o2 = t3 << 25 | t2 >> 26;
	uint64_t o3 = t4 << 12 | t3 >> 39;
	uint8_t *b0 = output;
	uint8_t *b1 = output + 8;
	uint8_t *b2 = output + 16;
	uint8_t *b3 = output + 24;
	*(uint64_t *)b0 = htole64(o0);
	*(uint64_t *)b1 = htole64(o1);
	*(uint64_t *)b2 = htole64(o2);
	*(uint64_t *)b3 = htole64(o3);
}

static __always_inline void format_fcontract(uint8_t *output, uint64_t *input)
{
	format_fcontract_first_carry_full(input);
	format_fcontract_second_carry_full(input);
	format_fcontract_trim(input);
	format_fcontract_store(output, input);
}

static __always_inline void format_scalar_of_point(uint8_t *scalar, uint64_t *point)
{
	uint64_t *x = point;
	uint64_t *z = point + 5;
	uint64_t buf[10] __aligned(32) = { 0 };
	uint64_t *zmone = buf;
	uint64_t *sc = buf + 5;
	crecip(zmone, z);
	fmul(sc, x, zmone);
	format_fcontract(scalar, sc);
}

void curve25519(uint8_t mypublic[static CURVE25519_POINT_SIZE], const uint8_t secret[static CURVE25519_POINT_SIZE], const uint8_t basepoint[static CURVE25519_POINT_SIZE])
{
	uint64_t buf0[10] __aligned(32) = { 0 };
	uint64_t *x0 = buf0;
	uint64_t *z = buf0 + 5;
	uint64_t *q;
	format_fexpand(x0, basepoint);
	z[0] = 1;
	q = buf0;
	{
		uint8_t e[32] __aligned(32) = { 0 };
		uint8_t *scalar;
		memcpy(e, secret, 32);
		curve25519_normalize_secret(e);
		scalar = e;
		{
			uint64_t buf[15] = { 0 };
			uint64_t *nq = buf;
			uint64_t *x = nq;
			x[0] = 1;
			ladder_cmult(nq, scalar, q);
			format_scalar_of_point(mypublic, nq);
		}
	}
}
#else
/* fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9].
 * fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
 * Multiplication and carrying produce fe from fe_loose.
 */
typedef struct fe { uint32_t v[10]; } fe;

/* fe_loose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc.
 * Addition and subtraction produce fe_loose from (fe, fe).
 */
typedef struct fe_loose { uint32_t v[10]; } fe_loose;

static __always_inline void fe_frombytes_impl(uint32_t h[10], const uint8_t *s)
{
	/* Ignores top bit of s. */
	uint32_t a0 = le32toh(*(uint32_t *)(s));
	uint32_t a1 = le32toh(*(uint32_t *)(s+4));
	uint32_t a2 = le32toh(*(uint32_t *)(s+8));
	uint32_t a3 = le32toh(*(uint32_t *)(s+12));
	uint32_t a4 = le32toh(*(uint32_t *)(s+16));
	uint32_t a5 = le32toh(*(uint32_t *)(s+20));
	uint32_t a6 = le32toh(*(uint32_t *)(s+24));
	uint32_t a7 = le32toh(*(uint32_t *)(s+28));
	h[0] = a0&((1<<26)-1);                    /* 26 used, 32-26 left.   26 */
	h[1] = (a0>>26) | ((a1&((1<<19)-1))<< 6); /* (32-26) + 19 =  6+19 = 25 */
	h[2] = (a1>>19) | ((a2&((1<<13)-1))<<13); /* (32-19) + 13 = 13+13 = 26 */
	h[3] = (a2>>13) | ((a3&((1<< 6)-1))<<19); /* (32-13) +  6 = 19+ 6 = 25 */
	h[4] = (a3>> 6);                          /* (32- 6)              = 26 */
	h[5] = a4&((1<<25)-1);                    /*                        25 */
	h[6] = (a4>>25) | ((a5&((1<<19)-1))<< 7); /* (32-25) + 19 =  7+19 = 26 */
	h[7] = (a5>>19) | ((a6&((1<<12)-1))<<13); /* (32-19) + 12 = 13+12 = 25 */
	h[8] = (a6>>12) | ((a7&((1<< 6)-1))<<20); /* (32-12) +  6 = 20+ 6 = 26 */
	h[9] = (a7>> 6)&((1<<25)-1); /*                                     25 */
}

static __always_inline void fe_frombytes(fe *h, const uint8_t *s)
{
	fe_frombytes_impl(h->v, s);
}

static __always_inline uint8_t /*bool*/ addcarryx_u25(uint8_t /*bool*/ c, uint32_t a, uint32_t b, uint32_t *low)
{
	/* This function extracts 25 bits of result and 1 bit of carry (26 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	uint32_t x = a + b + c;
	*low = x & ((1 << 25) - 1);
	return (x >> 25) & 1;
}

static __always_inline uint8_t /*bool*/ addcarryx_u26(uint8_t /*bool*/ c, uint32_t a, uint32_t b, uint32_t *low)
{
	/* This function extracts 26 bits of result and 1 bit of carry (27 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	uint32_t x = a + b + c;
	*low = x & ((1 << 26) - 1);
	return (x >> 26) & 1;
}

static __always_inline uint8_t /*bool*/ subborrow_u25(uint8_t /*bool*/ c, uint32_t a, uint32_t b, uint32_t *low)
{
	/* This function extracts 25 bits of result and 1 bit of borrow (26 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	uint32_t x = a - b - c;
	*low = x & ((1 << 25) - 1);
	return x >> 31;
}

static __always_inline uint8_t /*bool*/ subborrow_u26(uint8_t /*bool*/ c, uint32_t a, uint32_t b, uint32_t *low)
{
	/* This function extracts 26 bits of result and 1 bit of borrow (27 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	uint32_t x = a - b - c;
	*low = x & ((1 << 26) - 1);
	return x >> 31;
}

static __always_inline uint32_t cmovznz32(uint32_t t, uint32_t z, uint32_t nz)
{
	t = -!!t; /* all set if nonzero, 0 if 0 */
	return (t&nz) | ((~t)&z);
}

static __always_inline void fe_freeze(uint32_t out[10], const uint32_t in1[10])
{
	{ const uint32_t x17 = in1[9];
	{ const uint32_t x18 = in1[8];
	{ const uint32_t x16 = in1[7];
	{ const uint32_t x14 = in1[6];
	{ const uint32_t x12 = in1[5];
	{ const uint32_t x10 = in1[4];
	{ const uint32_t x8 = in1[3];
	{ const uint32_t x6 = in1[2];
	{ const uint32_t x4 = in1[1];
	{ const uint32_t x2 = in1[0];
	{ uint32_t x20; uint8_t/*bool*/ x21 = subborrow_u26(0x0, x2, 0x3ffffed, &x20);
	{ uint32_t x23; uint8_t/*bool*/ x24 = subborrow_u25(x21, x4, 0x1ffffff, &x23);
	{ uint32_t x26; uint8_t/*bool*/ x27 = subborrow_u26(x24, x6, 0x3ffffff, &x26);
	{ uint32_t x29; uint8_t/*bool*/ x30 = subborrow_u25(x27, x8, 0x1ffffff, &x29);
	{ uint32_t x32; uint8_t/*bool*/ x33 = subborrow_u26(x30, x10, 0x3ffffff, &x32);
	{ uint32_t x35; uint8_t/*bool*/ x36 = subborrow_u25(x33, x12, 0x1ffffff, &x35);
	{ uint32_t x38; uint8_t/*bool*/ x39 = subborrow_u26(x36, x14, 0x3ffffff, &x38);
	{ uint32_t x41; uint8_t/*bool*/ x42 = subborrow_u25(x39, x16, 0x1ffffff, &x41);
	{ uint32_t x44; uint8_t/*bool*/ x45 = subborrow_u26(x42, x18, 0x3ffffff, &x44);
	{ uint32_t x47; uint8_t/*bool*/ x48 = subborrow_u25(x45, x17, 0x1ffffff, &x47);
	{ uint32_t x49 = cmovznz32(x48, 0x0, 0xffffffff);
	{ uint32_t x50 = (x49 & 0x3ffffed);
	{ uint32_t x52; uint8_t/*bool*/ x53 = addcarryx_u26(0x0, x20, x50, &x52);
	{ uint32_t x54 = (x49 & 0x1ffffff);
	{ uint32_t x56; uint8_t/*bool*/ x57 = addcarryx_u25(x53, x23, x54, &x56);
	{ uint32_t x58 = (x49 & 0x3ffffff);
	{ uint32_t x60; uint8_t/*bool*/ x61 = addcarryx_u26(x57, x26, x58, &x60);
	{ uint32_t x62 = (x49 & 0x1ffffff);
	{ uint32_t x64; uint8_t/*bool*/ x65 = addcarryx_u25(x61, x29, x62, &x64);
	{ uint32_t x66 = (x49 & 0x3ffffff);
	{ uint32_t x68; uint8_t/*bool*/ x69 = addcarryx_u26(x65, x32, x66, &x68);
	{ uint32_t x70 = (x49 & 0x1ffffff);
	{ uint32_t x72; uint8_t/*bool*/ x73 = addcarryx_u25(x69, x35, x70, &x72);
	{ uint32_t x74 = (x49 & 0x3ffffff);
	{ uint32_t x76; uint8_t/*bool*/ x77 = addcarryx_u26(x73, x38, x74, &x76);
	{ uint32_t x78 = (x49 & 0x1ffffff);
	{ uint32_t x80; uint8_t/*bool*/ x81 = addcarryx_u25(x77, x41, x78, &x80);
	{ uint32_t x82 = (x49 & 0x3ffffff);
	{ uint32_t x84; uint8_t/*bool*/ x85 = addcarryx_u26(x81, x44, x82, &x84);
	{ uint32_t x86 = (x49 & 0x1ffffff);
	{ uint32_t x88; addcarryx_u25(x85, x47, x86, &x88);
	out[0] = x52;
	out[1] = x56;
	out[2] = x60;
	out[3] = x64;
	out[4] = x68;
	out[5] = x72;
	out[6] = x76;
	out[7] = x80;
	out[8] = x84;
	out[9] = x88;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

static __always_inline void fe_tobytes(uint8_t s[32], const fe *f)
{
	uint32_t h[10];
	fe_freeze(h, f->v);
	s[0] = h[0] >> 0;
	s[1] = h[0] >> 8;
	s[2] = h[0] >> 16;
	s[3] = (h[0] >> 24) | (h[1] << 2);
	s[4] = h[1] >> 6;
	s[5] = h[1] >> 14;
	s[6] = (h[1] >> 22) | (h[2] << 3);
	s[7] = h[2] >> 5;
	s[8] = h[2] >> 13;
	s[9] = (h[2] >> 21) | (h[3] << 5);
	s[10] = h[3] >> 3;
	s[11] = h[3] >> 11;
	s[12] = (h[3] >> 19) | (h[4] << 6);
	s[13] = h[4] >> 2;
	s[14] = h[4] >> 10;
	s[15] = h[4] >> 18;
	s[16] = h[5] >> 0;
	s[17] = h[5] >> 8;
	s[18] = h[5] >> 16;
	s[19] = (h[5] >> 24) | (h[6] << 1);
	s[20] = h[6] >> 7;
	s[21] = h[6] >> 15;
	s[22] = (h[6] >> 23) | (h[7] << 3);
	s[23] = h[7] >> 5;
	s[24] = h[7] >> 13;
	s[25] = (h[7] >> 21) | (h[8] << 4);
	s[26] = h[8] >> 4;
	s[27] = h[8] >> 12;
	s[28] = (h[8] >> 20) | (h[9] << 6);
	s[29] = h[9] >> 2;
	s[30] = h[9] >> 10;
	s[31] = h[9] >> 18;
}

/* h = f */
static __always_inline void fe_copy(fe *h, const fe *f)
{
	memmove(h, f, sizeof(uint32_t) * 10);
}

static __always_inline void fe_copy_lt(fe_loose *h, const fe *f)
{
	memmove(h, f, sizeof(uint32_t) * 10);
}

/* h = 0 */
static __always_inline void fe_0(fe *h)
{
	memset(h, 0, sizeof(uint32_t) * 10);
}

/* h = 1 */
static __always_inline void fe_1(fe *h)
{
	memset(h, 0, sizeof(uint32_t) * 10);
	h->v[0] = 1;
}

static __always_inline void fe_add_impl(uint32_t out[10], const uint32_t in1[10], const uint32_t in2[10])
{
	{ const uint32_t x20 = in1[9];
	{ const uint32_t x21 = in1[8];
	{ const uint32_t x19 = in1[7];
	{ const uint32_t x17 = in1[6];
	{ const uint32_t x15 = in1[5];
	{ const uint32_t x13 = in1[4];
	{ const uint32_t x11 = in1[3];
	{ const uint32_t x9 = in1[2];
	{ const uint32_t x7 = in1[1];
	{ const uint32_t x5 = in1[0];
	{ const uint32_t x38 = in2[9];
	{ const uint32_t x39 = in2[8];
	{ const uint32_t x37 = in2[7];
	{ const uint32_t x35 = in2[6];
	{ const uint32_t x33 = in2[5];
	{ const uint32_t x31 = in2[4];
	{ const uint32_t x29 = in2[3];
	{ const uint32_t x27 = in2[2];
	{ const uint32_t x25 = in2[1];
	{ const uint32_t x23 = in2[0];
	out[0] = (x5 + x23);
	out[1] = (x7 + x25);
	out[2] = (x9 + x27);
	out[3] = (x11 + x29);
	out[4] = (x13 + x31);
	out[5] = (x15 + x33);
	out[6] = (x17 + x35);
	out[7] = (x19 + x37);
	out[8] = (x21 + x39);
	out[9] = (x20 + x38);
	}}}}}}}}}}}}}}}}}}}}
}

/* h = f + g
 * Can overlap h with f or g.
 */
static __always_inline void fe_add(fe_loose *h, const fe *f, const fe *g)
{
	fe_add_impl(h->v, f->v, g->v);
}

static __always_inline void fe_sub_impl(uint32_t out[10], const uint32_t in1[10], const uint32_t in2[10])
{
	{ const uint32_t x20 = in1[9];
	{ const uint32_t x21 = in1[8];
	{ const uint32_t x19 = in1[7];
	{ const uint32_t x17 = in1[6];
	{ const uint32_t x15 = in1[5];
	{ const uint32_t x13 = in1[4];
	{ const uint32_t x11 = in1[3];
	{ const uint32_t x9 = in1[2];
	{ const uint32_t x7 = in1[1];
	{ const uint32_t x5 = in1[0];
	{ const uint32_t x38 = in2[9];
	{ const uint32_t x39 = in2[8];
	{ const uint32_t x37 = in2[7];
	{ const uint32_t x35 = in2[6];
	{ const uint32_t x33 = in2[5];
	{ const uint32_t x31 = in2[4];
	{ const uint32_t x29 = in2[3];
	{ const uint32_t x27 = in2[2];
	{ const uint32_t x25 = in2[1];
	{ const uint32_t x23 = in2[0];
	out[0] = ((0x7ffffda + x5) - x23);
	out[1] = ((0x3fffffe + x7) - x25);
	out[2] = ((0x7fffffe + x9) - x27);
	out[3] = ((0x3fffffe + x11) - x29);
	out[4] = ((0x7fffffe + x13) - x31);
	out[5] = ((0x3fffffe + x15) - x33);
	out[6] = ((0x7fffffe + x17) - x35);
	out[7] = ((0x3fffffe + x19) - x37);
	out[8] = ((0x7fffffe + x21) - x39);
	out[9] = ((0x3fffffe + x20) - x38);
	}}}}}}}}}}}}}}}}}}}}
}

/* h = f - g
 * Can overlap h with f or g.
 */
static __always_inline void fe_sub(fe_loose *h, const fe *f, const fe *g)
{
	fe_sub_impl(h->v, f->v, g->v);
}

static __always_inline void fe_mul_impl(uint32_t out[10], const uint32_t in1[10], const uint32_t in2[10])
{
	{ const uint32_t x20 = in1[9];
	{ const uint32_t x21 = in1[8];
	{ const uint32_t x19 = in1[7];
	{ const uint32_t x17 = in1[6];
	{ const uint32_t x15 = in1[5];
	{ const uint32_t x13 = in1[4];
	{ const uint32_t x11 = in1[3];
	{ const uint32_t x9 = in1[2];
	{ const uint32_t x7 = in1[1];
	{ const uint32_t x5 = in1[0];
	{ const uint32_t x38 = in2[9];
	{ const uint32_t x39 = in2[8];
	{ const uint32_t x37 = in2[7];
	{ const uint32_t x35 = in2[6];
	{ const uint32_t x33 = in2[5];
	{ const uint32_t x31 = in2[4];
	{ const uint32_t x29 = in2[3];
	{ const uint32_t x27 = in2[2];
	{ const uint32_t x25 = in2[1];
	{ const uint32_t x23 = in2[0];
	{ uint64_t x40 = ((uint64_t)x23 * x5);
	{ uint64_t x41 = (((uint64_t)x23 * x7) + ((uint64_t)x25 * x5));
	{ uint64_t x42 = ((((uint64_t)(0x2 * x25) * x7) + ((uint64_t)x23 * x9)) + ((uint64_t)x27 * x5));
	{ uint64_t x43 = (((((uint64_t)x25 * x9) + ((uint64_t)x27 * x7)) + ((uint64_t)x23 * x11)) + ((uint64_t)x29 * x5));
	{ uint64_t x44 = (((((uint64_t)x27 * x9) + (0x2 * (((uint64_t)x25 * x11) + ((uint64_t)x29 * x7)))) + ((uint64_t)x23 * x13)) + ((uint64_t)x31 * x5));
	{ uint64_t x45 = (((((((uint64_t)x27 * x11) + ((uint64_t)x29 * x9)) + ((uint64_t)x25 * x13)) + ((uint64_t)x31 * x7)) + ((uint64_t)x23 * x15)) + ((uint64_t)x33 * x5));
	{ uint64_t x46 = (((((0x2 * ((((uint64_t)x29 * x11) + ((uint64_t)x25 * x15)) + ((uint64_t)x33 * x7))) + ((uint64_t)x27 * x13)) + ((uint64_t)x31 * x9)) + ((uint64_t)x23 * x17)) + ((uint64_t)x35 * x5));
	{ uint64_t x47 = (((((((((uint64_t)x29 * x13) + ((uint64_t)x31 * x11)) + ((uint64_t)x27 * x15)) + ((uint64_t)x33 * x9)) + ((uint64_t)x25 * x17)) + ((uint64_t)x35 * x7)) + ((uint64_t)x23 * x19)) + ((uint64_t)x37 * x5));
	{ uint64_t x48 = (((((((uint64_t)x31 * x13) + (0x2 * (((((uint64_t)x29 * x15) + ((uint64_t)x33 * x11)) + ((uint64_t)x25 * x19)) + ((uint64_t)x37 * x7)))) + ((uint64_t)x27 * x17)) + ((uint64_t)x35 * x9)) + ((uint64_t)x23 * x21)) + ((uint64_t)x39 * x5));
	{ uint64_t x49 = (((((((((((uint64_t)x31 * x15) + ((uint64_t)x33 * x13)) + ((uint64_t)x29 * x17)) + ((uint64_t)x35 * x11)) + ((uint64_t)x27 * x19)) + ((uint64_t)x37 * x9)) + ((uint64_t)x25 * x21)) + ((uint64_t)x39 * x7)) + ((uint64_t)x23 * x20)) + ((uint64_t)x38 * x5));
	{ uint64_t x50 = (((((0x2 * ((((((uint64_t)x33 * x15) + ((uint64_t)x29 * x19)) + ((uint64_t)x37 * x11)) + ((uint64_t)x25 * x20)) + ((uint64_t)x38 * x7))) + ((uint64_t)x31 * x17)) + ((uint64_t)x35 * x13)) + ((uint64_t)x27 * x21)) + ((uint64_t)x39 * x9));
	{ uint64_t x51 = (((((((((uint64_t)x33 * x17) + ((uint64_t)x35 * x15)) + ((uint64_t)x31 * x19)) + ((uint64_t)x37 * x13)) + ((uint64_t)x29 * x21)) + ((uint64_t)x39 * x11)) + ((uint64_t)x27 * x20)) + ((uint64_t)x38 * x9));
	{ uint64_t x52 = (((((uint64_t)x35 * x17) + (0x2 * (((((uint64_t)x33 * x19) + ((uint64_t)x37 * x15)) + ((uint64_t)x29 * x20)) + ((uint64_t)x38 * x11)))) + ((uint64_t)x31 * x21)) + ((uint64_t)x39 * x13));
	{ uint64_t x53 = (((((((uint64_t)x35 * x19) + ((uint64_t)x37 * x17)) + ((uint64_t)x33 * x21)) + ((uint64_t)x39 * x15)) + ((uint64_t)x31 * x20)) + ((uint64_t)x38 * x13));
	{ uint64_t x54 = (((0x2 * ((((uint64_t)x37 * x19) + ((uint64_t)x33 * x20)) + ((uint64_t)x38 * x15))) + ((uint64_t)x35 * x21)) + ((uint64_t)x39 * x17));
	{ uint64_t x55 = (((((uint64_t)x37 * x21) + ((uint64_t)x39 * x19)) + ((uint64_t)x35 * x20)) + ((uint64_t)x38 * x17));
	{ uint64_t x56 = (((uint64_t)x39 * x21) + (0x2 * (((uint64_t)x37 * x20) + ((uint64_t)x38 * x19))));
	{ uint64_t x57 = (((uint64_t)x39 * x20) + ((uint64_t)x38 * x21));
	{ uint64_t x58 = ((uint64_t)(0x2 * x38) * x20);
	{ uint64_t x59 = (x48 + (x58 << 0x4));
	{ uint64_t x60 = (x59 + (x58 << 0x1));
	{ uint64_t x61 = (x60 + x58);
	{ uint64_t x62 = (x47 + (x57 << 0x4));
	{ uint64_t x63 = (x62 + (x57 << 0x1));
	{ uint64_t x64 = (x63 + x57);
	{ uint64_t x65 = (x46 + (x56 << 0x4));
	{ uint64_t x66 = (x65 + (x56 << 0x1));
	{ uint64_t x67 = (x66 + x56);
	{ uint64_t x68 = (x45 + (x55 << 0x4));
	{ uint64_t x69 = (x68 + (x55 << 0x1));
	{ uint64_t x70 = (x69 + x55);
	{ uint64_t x71 = (x44 + (x54 << 0x4));
	{ uint64_t x72 = (x71 + (x54 << 0x1));
	{ uint64_t x73 = (x72 + x54);
	{ uint64_t x74 = (x43 + (x53 << 0x4));
	{ uint64_t x75 = (x74 + (x53 << 0x1));
	{ uint64_t x76 = (x75 + x53);
	{ uint64_t x77 = (x42 + (x52 << 0x4));
	{ uint64_t x78 = (x77 + (x52 << 0x1));
	{ uint64_t x79 = (x78 + x52);
	{ uint64_t x80 = (x41 + (x51 << 0x4));
	{ uint64_t x81 = (x80 + (x51 << 0x1));
	{ uint64_t x82 = (x81 + x51);
	{ uint64_t x83 = (x40 + (x50 << 0x4));
	{ uint64_t x84 = (x83 + (x50 << 0x1));
	{ uint64_t x85 = (x84 + x50);
	{ uint64_t x86 = (x85 >> 0x1a);
	{ uint32_t x87 = ((uint32_t)x85 & 0x3ffffff);
	{ uint64_t x88 = (x86 + x82);
	{ uint64_t x89 = (x88 >> 0x19);
	{ uint32_t x90 = ((uint32_t)x88 & 0x1ffffff);
	{ uint64_t x91 = (x89 + x79);
	{ uint64_t x92 = (x91 >> 0x1a);
	{ uint32_t x93 = ((uint32_t)x91 & 0x3ffffff);
	{ uint64_t x94 = (x92 + x76);
	{ uint64_t x95 = (x94 >> 0x19);
	{ uint32_t x96 = ((uint32_t)x94 & 0x1ffffff);
	{ uint64_t x97 = (x95 + x73);
	{ uint64_t x98 = (x97 >> 0x1a);
	{ uint32_t x99 = ((uint32_t)x97 & 0x3ffffff);
	{ uint64_t x100 = (x98 + x70);
	{ uint64_t x101 = (x100 >> 0x19);
	{ uint32_t x102 = ((uint32_t)x100 & 0x1ffffff);
	{ uint64_t x103 = (x101 + x67);
	{ uint64_t x104 = (x103 >> 0x1a);
	{ uint32_t x105 = ((uint32_t)x103 & 0x3ffffff);
	{ uint64_t x106 = (x104 + x64);
	{ uint64_t x107 = (x106 >> 0x19);
	{ uint32_t x108 = ((uint32_t)x106 & 0x1ffffff);
	{ uint64_t x109 = (x107 + x61);
	{ uint64_t x110 = (x109 >> 0x1a);
	{ uint32_t x111 = ((uint32_t)x109 & 0x3ffffff);
	{ uint64_t x112 = (x110 + x49);
	{ uint64_t x113 = (x112 >> 0x19);
	{ uint32_t x114 = ((uint32_t)x112 & 0x1ffffff);
	{ uint64_t x115 = (x87 + (0x13 * x113));
	{ uint32_t x116 = (uint32_t) (x115 >> 0x1a);
	{ uint32_t x117 = ((uint32_t)x115 & 0x3ffffff);
	{ uint32_t x118 = (x116 + x90);
	{ uint32_t x119 = (x118 >> 0x19);
	{ uint32_t x120 = (x118 & 0x1ffffff);
	out[0] = x117;
	out[1] = x120;
	out[2] = (x119 + x93);
	out[3] = x96;
	out[4] = x99;
	out[5] = x102;
	out[6] = x105;
	out[7] = x108;
	out[8] = x111;
	out[9] = x114;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

static __always_inline void fe_mul_ttt(fe *h, const fe *f, const fe *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static __always_inline void fe_mul_tlt(fe *h, const fe_loose *f, const fe *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static __always_inline void fe_mul_tll(fe *h, const fe_loose *f, const fe_loose *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static __always_inline void fe_sqr_impl(uint32_t out[10], const uint32_t in1[10])
{
	{ const uint32_t x17 = in1[9];
	{ const uint32_t x18 = in1[8];
	{ const uint32_t x16 = in1[7];
	{ const uint32_t x14 = in1[6];
	{ const uint32_t x12 = in1[5];
	{ const uint32_t x10 = in1[4];
	{ const uint32_t x8 = in1[3];
	{ const uint32_t x6 = in1[2];
	{ const uint32_t x4 = in1[1];
	{ const uint32_t x2 = in1[0];
	{ uint64_t x19 = ((uint64_t)x2 * x2);
	{ uint64_t x20 = ((uint64_t)(0x2 * x2) * x4);
	{ uint64_t x21 = (0x2 * (((uint64_t)x4 * x4) + ((uint64_t)x2 * x6)));
	{ uint64_t x22 = (0x2 * (((uint64_t)x4 * x6) + ((uint64_t)x2 * x8)));
	{ uint64_t x23 = ((((uint64_t)x6 * x6) + ((uint64_t)(0x4 * x4) * x8)) + ((uint64_t)(0x2 * x2) * x10));
	{ uint64_t x24 = (0x2 * ((((uint64_t)x6 * x8) + ((uint64_t)x4 * x10)) + ((uint64_t)x2 * x12)));
	{ uint64_t x25 = (0x2 * (((((uint64_t)x8 * x8) + ((uint64_t)x6 * x10)) + ((uint64_t)x2 * x14)) + ((uint64_t)(0x2 * x4) * x12)));
	{ uint64_t x26 = (0x2 * (((((uint64_t)x8 * x10) + ((uint64_t)x6 * x12)) + ((uint64_t)x4 * x14)) + ((uint64_t)x2 * x16)));
	{ uint64_t x27 = (((uint64_t)x10 * x10) + (0x2 * ((((uint64_t)x6 * x14) + ((uint64_t)x2 * x18)) + (0x2 * (((uint64_t)x4 * x16) + ((uint64_t)x8 * x12))))));
	{ uint64_t x28 = (0x2 * ((((((uint64_t)x10 * x12) + ((uint64_t)x8 * x14)) + ((uint64_t)x6 * x16)) + ((uint64_t)x4 * x18)) + ((uint64_t)x2 * x17)));
	{ uint64_t x29 = (0x2 * (((((uint64_t)x12 * x12) + ((uint64_t)x10 * x14)) + ((uint64_t)x6 * x18)) + (0x2 * (((uint64_t)x8 * x16) + ((uint64_t)x4 * x17)))));
	{ uint64_t x30 = (0x2 * (((((uint64_t)x12 * x14) + ((uint64_t)x10 * x16)) + ((uint64_t)x8 * x18)) + ((uint64_t)x6 * x17)));
	{ uint64_t x31 = (((uint64_t)x14 * x14) + (0x2 * (((uint64_t)x10 * x18) + (0x2 * (((uint64_t)x12 * x16) + ((uint64_t)x8 * x17))))));
	{ uint64_t x32 = (0x2 * ((((uint64_t)x14 * x16) + ((uint64_t)x12 * x18)) + ((uint64_t)x10 * x17)));
	{ uint64_t x33 = (0x2 * ((((uint64_t)x16 * x16) + ((uint64_t)x14 * x18)) + ((uint64_t)(0x2 * x12) * x17)));
	{ uint64_t x34 = (0x2 * (((uint64_t)x16 * x18) + ((uint64_t)x14 * x17)));
	{ uint64_t x35 = (((uint64_t)x18 * x18) + ((uint64_t)(0x4 * x16) * x17));
	{ uint64_t x36 = ((uint64_t)(0x2 * x18) * x17);
	{ uint64_t x37 = ((uint64_t)(0x2 * x17) * x17);
	{ uint64_t x38 = (x27 + (x37 << 0x4));
	{ uint64_t x39 = (x38 + (x37 << 0x1));
	{ uint64_t x40 = (x39 + x37);
	{ uint64_t x41 = (x26 + (x36 << 0x4));
	{ uint64_t x42 = (x41 + (x36 << 0x1));
	{ uint64_t x43 = (x42 + x36);
	{ uint64_t x44 = (x25 + (x35 << 0x4));
	{ uint64_t x45 = (x44 + (x35 << 0x1));
	{ uint64_t x46 = (x45 + x35);
	{ uint64_t x47 = (x24 + (x34 << 0x4));
	{ uint64_t x48 = (x47 + (x34 << 0x1));
	{ uint64_t x49 = (x48 + x34);
	{ uint64_t x50 = (x23 + (x33 << 0x4));
	{ uint64_t x51 = (x50 + (x33 << 0x1));
	{ uint64_t x52 = (x51 + x33);
	{ uint64_t x53 = (x22 + (x32 << 0x4));
	{ uint64_t x54 = (x53 + (x32 << 0x1));
	{ uint64_t x55 = (x54 + x32);
	{ uint64_t x56 = (x21 + (x31 << 0x4));
	{ uint64_t x57 = (x56 + (x31 << 0x1));
	{ uint64_t x58 = (x57 + x31);
	{ uint64_t x59 = (x20 + (x30 << 0x4));
	{ uint64_t x60 = (x59 + (x30 << 0x1));
	{ uint64_t x61 = (x60 + x30);
	{ uint64_t x62 = (x19 + (x29 << 0x4));
	{ uint64_t x63 = (x62 + (x29 << 0x1));
	{ uint64_t x64 = (x63 + x29);
	{ uint64_t x65 = (x64 >> 0x1a);
	{ uint32_t x66 = ((uint32_t)x64 & 0x3ffffff);
	{ uint64_t x67 = (x65 + x61);
	{ uint64_t x68 = (x67 >> 0x19);
	{ uint32_t x69 = ((uint32_t)x67 & 0x1ffffff);
	{ uint64_t x70 = (x68 + x58);
	{ uint64_t x71 = (x70 >> 0x1a);
	{ uint32_t x72 = ((uint32_t)x70 & 0x3ffffff);
	{ uint64_t x73 = (x71 + x55);
	{ uint64_t x74 = (x73 >> 0x19);
	{ uint32_t x75 = ((uint32_t)x73 & 0x1ffffff);
	{ uint64_t x76 = (x74 + x52);
	{ uint64_t x77 = (x76 >> 0x1a);
	{ uint32_t x78 = ((uint32_t)x76 & 0x3ffffff);
	{ uint64_t x79 = (x77 + x49);
	{ uint64_t x80 = (x79 >> 0x19);
	{ uint32_t x81 = ((uint32_t)x79 & 0x1ffffff);
	{ uint64_t x82 = (x80 + x46);
	{ uint64_t x83 = (x82 >> 0x1a);
	{ uint32_t x84 = ((uint32_t)x82 & 0x3ffffff);
	{ uint64_t x85 = (x83 + x43);
	{ uint64_t x86 = (x85 >> 0x19);
	{ uint32_t x87 = ((uint32_t)x85 & 0x1ffffff);
	{ uint64_t x88 = (x86 + x40);
	{ uint64_t x89 = (x88 >> 0x1a);
	{ uint32_t x90 = ((uint32_t)x88 & 0x3ffffff);
	{ uint64_t x91 = (x89 + x28);
	{ uint64_t x92 = (x91 >> 0x19);
	{ uint32_t x93 = ((uint32_t)x91 & 0x1ffffff);
	{ uint64_t x94 = (x66 + (0x13 * x92));
	{ uint32_t x95 = (uint32_t) (x94 >> 0x1a);
	{ uint32_t x96 = ((uint32_t)x94 & 0x3ffffff);
	{ uint32_t x97 = (x95 + x69);
	{ uint32_t x98 = (x97 >> 0x19);
	{ uint32_t x99 = (x97 & 0x1ffffff);
	out[0] = x96;
	out[1] = x99;
	out[2] = (x98 + x72);
	out[3] = x75;
	out[4] = x78;
	out[5] = x81;
	out[6] = x84;
	out[7] = x87;
	out[8] = x90;
	out[9] = x93;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

static __always_inline void fe_sq_tl(fe *h, const fe_loose *f)
{
	fe_sqr_impl(h->v, f->v);
}

static __always_inline void fe_sq_tt(fe *h, const fe *f)
{
	fe_sqr_impl(h->v, f->v);
}

static __always_inline void fe_loose_invert(fe *out, const fe_loose *z)
{
	fe t0;
	fe t1;
	fe t2;
	fe t3;
	int i;

	fe_sq_tl(&t0, z);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 2; ++i)
		fe_sq_tt(&t1, &t1);
	fe_mul_tlt(&t1, z, &t1);
	fe_mul_ttt(&t0, &t0, &t1);
	fe_sq_tt(&t2, &t0);
	fe_mul_ttt(&t1, &t1, &t2);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 5; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 10; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 20; ++i)
		fe_sq_tt(&t3, &t3);
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 10; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 50; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 100; ++i)
		fe_sq_tt(&t3, &t3);
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 50; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t1, &t1);
	for (i = 1; i < 5; ++i)
		fe_sq_tt(&t1, &t1);
	fe_mul_ttt(out, &t1, &t0);
}

static __always_inline void fe_invert(fe *out, const fe *z)
{
	fe_loose l;
	fe_copy_lt(&l, z);
	fe_loose_invert(out, &l);
}

/* Replace (f,g) with (g,f) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}
 */
static __always_inline void fe_cswap(fe *f, fe *g, unsigned int b)
{
	unsigned i;
	b = 0-b;
	for (i = 0; i < 10; i++) {
		uint32_t x = f->v[i] ^ g->v[i];
		x &= b;
		f->v[i] ^= x;
		g->v[i] ^= x;
	}
}

/* NOTE: based on fiat-crypto fe_mul, edited for in2=121666, 0, 0.*/
static __always_inline void fe_mul_121666_impl(uint32_t out[10], const uint32_t in1[10])
{
	{ const uint32_t x20 = in1[9];
	{ const uint32_t x21 = in1[8];
	{ const uint32_t x19 = in1[7];
	{ const uint32_t x17 = in1[6];
	{ const uint32_t x15 = in1[5];
	{ const uint32_t x13 = in1[4];
	{ const uint32_t x11 = in1[3];
	{ const uint32_t x9 = in1[2];
	{ const uint32_t x7 = in1[1];
	{ const uint32_t x5 = in1[0];
	{ const uint32_t x38 = 0;
	{ const uint32_t x39 = 0;
	{ const uint32_t x37 = 0;
	{ const uint32_t x35 = 0;
	{ const uint32_t x33 = 0;
	{ const uint32_t x31 = 0;
	{ const uint32_t x29 = 0;
	{ const uint32_t x27 = 0;
	{ const uint32_t x25 = 0;
	{ const uint32_t x23 = 121666;
	{ uint64_t x40 = ((uint64_t)x23 * x5);
	{ uint64_t x41 = (((uint64_t)x23 * x7) + ((uint64_t)x25 * x5));
	{ uint64_t x42 = ((((uint64_t)(0x2 * x25) * x7) + ((uint64_t)x23 * x9)) + ((uint64_t)x27 * x5));
	{ uint64_t x43 = (((((uint64_t)x25 * x9) + ((uint64_t)x27 * x7)) + ((uint64_t)x23 * x11)) + ((uint64_t)x29 * x5));
	{ uint64_t x44 = (((((uint64_t)x27 * x9) + (0x2 * (((uint64_t)x25 * x11) + ((uint64_t)x29 * x7)))) + ((uint64_t)x23 * x13)) + ((uint64_t)x31 * x5));
	{ uint64_t x45 = (((((((uint64_t)x27 * x11) + ((uint64_t)x29 * x9)) + ((uint64_t)x25 * x13)) + ((uint64_t)x31 * x7)) + ((uint64_t)x23 * x15)) + ((uint64_t)x33 * x5));
	{ uint64_t x46 = (((((0x2 * ((((uint64_t)x29 * x11) + ((uint64_t)x25 * x15)) + ((uint64_t)x33 * x7))) + ((uint64_t)x27 * x13)) + ((uint64_t)x31 * x9)) + ((uint64_t)x23 * x17)) + ((uint64_t)x35 * x5));
	{ uint64_t x47 = (((((((((uint64_t)x29 * x13) + ((uint64_t)x31 * x11)) + ((uint64_t)x27 * x15)) + ((uint64_t)x33 * x9)) + ((uint64_t)x25 * x17)) + ((uint64_t)x35 * x7)) + ((uint64_t)x23 * x19)) + ((uint64_t)x37 * x5));
	{ uint64_t x48 = (((((((uint64_t)x31 * x13) + (0x2 * (((((uint64_t)x29 * x15) + ((uint64_t)x33 * x11)) + ((uint64_t)x25 * x19)) + ((uint64_t)x37 * x7)))) + ((uint64_t)x27 * x17)) + ((uint64_t)x35 * x9)) + ((uint64_t)x23 * x21)) + ((uint64_t)x39 * x5));
	{ uint64_t x49 = (((((((((((uint64_t)x31 * x15) + ((uint64_t)x33 * x13)) + ((uint64_t)x29 * x17)) + ((uint64_t)x35 * x11)) + ((uint64_t)x27 * x19)) + ((uint64_t)x37 * x9)) + ((uint64_t)x25 * x21)) + ((uint64_t)x39 * x7)) + ((uint64_t)x23 * x20)) + ((uint64_t)x38 * x5));
	{ uint64_t x50 = (((((0x2 * ((((((uint64_t)x33 * x15) + ((uint64_t)x29 * x19)) + ((uint64_t)x37 * x11)) + ((uint64_t)x25 * x20)) + ((uint64_t)x38 * x7))) + ((uint64_t)x31 * x17)) + ((uint64_t)x35 * x13)) + ((uint64_t)x27 * x21)) + ((uint64_t)x39 * x9));
	{ uint64_t x51 = (((((((((uint64_t)x33 * x17) + ((uint64_t)x35 * x15)) + ((uint64_t)x31 * x19)) + ((uint64_t)x37 * x13)) + ((uint64_t)x29 * x21)) + ((uint64_t)x39 * x11)) + ((uint64_t)x27 * x20)) + ((uint64_t)x38 * x9));
	{ uint64_t x52 = (((((uint64_t)x35 * x17) + (0x2 * (((((uint64_t)x33 * x19) + ((uint64_t)x37 * x15)) + ((uint64_t)x29 * x20)) + ((uint64_t)x38 * x11)))) + ((uint64_t)x31 * x21)) + ((uint64_t)x39 * x13));
	{ uint64_t x53 = (((((((uint64_t)x35 * x19) + ((uint64_t)x37 * x17)) + ((uint64_t)x33 * x21)) + ((uint64_t)x39 * x15)) + ((uint64_t)x31 * x20)) + ((uint64_t)x38 * x13));
	{ uint64_t x54 = (((0x2 * ((((uint64_t)x37 * x19) + ((uint64_t)x33 * x20)) + ((uint64_t)x38 * x15))) + ((uint64_t)x35 * x21)) + ((uint64_t)x39 * x17));
	{ uint64_t x55 = (((((uint64_t)x37 * x21) + ((uint64_t)x39 * x19)) + ((uint64_t)x35 * x20)) + ((uint64_t)x38 * x17));
	{ uint64_t x56 = (((uint64_t)x39 * x21) + (0x2 * (((uint64_t)x37 * x20) + ((uint64_t)x38 * x19))));
	{ uint64_t x57 = (((uint64_t)x39 * x20) + ((uint64_t)x38 * x21));
	{ uint64_t x58 = ((uint64_t)(0x2 * x38) * x20);
	{ uint64_t x59 = (x48 + (x58 << 0x4));
	{ uint64_t x60 = (x59 + (x58 << 0x1));
	{ uint64_t x61 = (x60 + x58);
	{ uint64_t x62 = (x47 + (x57 << 0x4));
	{ uint64_t x63 = (x62 + (x57 << 0x1));
	{ uint64_t x64 = (x63 + x57);
	{ uint64_t x65 = (x46 + (x56 << 0x4));
	{ uint64_t x66 = (x65 + (x56 << 0x1));
	{ uint64_t x67 = (x66 + x56);
	{ uint64_t x68 = (x45 + (x55 << 0x4));
	{ uint64_t x69 = (x68 + (x55 << 0x1));
	{ uint64_t x70 = (x69 + x55);
	{ uint64_t x71 = (x44 + (x54 << 0x4));
	{ uint64_t x72 = (x71 + (x54 << 0x1));
	{ uint64_t x73 = (x72 + x54);
	{ uint64_t x74 = (x43 + (x53 << 0x4));
	{ uint64_t x75 = (x74 + (x53 << 0x1));
	{ uint64_t x76 = (x75 + x53);
	{ uint64_t x77 = (x42 + (x52 << 0x4));
	{ uint64_t x78 = (x77 + (x52 << 0x1));
	{ uint64_t x79 = (x78 + x52);
	{ uint64_t x80 = (x41 + (x51 << 0x4));
	{ uint64_t x81 = (x80 + (x51 << 0x1));
	{ uint64_t x82 = (x81 + x51);
	{ uint64_t x83 = (x40 + (x50 << 0x4));
	{ uint64_t x84 = (x83 + (x50 << 0x1));
	{ uint64_t x85 = (x84 + x50);
	{ uint64_t x86 = (x85 >> 0x1a);
	{ uint32_t x87 = ((uint32_t)x85 & 0x3ffffff);
	{ uint64_t x88 = (x86 + x82);
	{ uint64_t x89 = (x88 >> 0x19);
	{ uint32_t x90 = ((uint32_t)x88 & 0x1ffffff);
	{ uint64_t x91 = (x89 + x79);
	{ uint64_t x92 = (x91 >> 0x1a);
	{ uint32_t x93 = ((uint32_t)x91 & 0x3ffffff);
	{ uint64_t x94 = (x92 + x76);
	{ uint64_t x95 = (x94 >> 0x19);
	{ uint32_t x96 = ((uint32_t)x94 & 0x1ffffff);
	{ uint64_t x97 = (x95 + x73);
	{ uint64_t x98 = (x97 >> 0x1a);
	{ uint32_t x99 = ((uint32_t)x97 & 0x3ffffff);
	{ uint64_t x100 = (x98 + x70);
	{ uint64_t x101 = (x100 >> 0x19);
	{ uint32_t x102 = ((uint32_t)x100 & 0x1ffffff);
	{ uint64_t x103 = (x101 + x67);
	{ uint64_t x104 = (x103 >> 0x1a);
	{ uint32_t x105 = ((uint32_t)x103 & 0x3ffffff);
	{ uint64_t x106 = (x104 + x64);
	{ uint64_t x107 = (x106 >> 0x19);
	{ uint32_t x108 = ((uint32_t)x106 & 0x1ffffff);
	{ uint64_t x109 = (x107 + x61);
	{ uint64_t x110 = (x109 >> 0x1a);
	{ uint32_t x111 = ((uint32_t)x109 & 0x3ffffff);
	{ uint64_t x112 = (x110 + x49);
	{ uint64_t x113 = (x112 >> 0x19);
	{ uint32_t x114 = ((uint32_t)x112 & 0x1ffffff);
	{ uint64_t x115 = (x87 + (0x13 * x113));
	{ uint32_t x116 = (uint32_t) (x115 >> 0x1a);
	{ uint32_t x117 = ((uint32_t)x115 & 0x3ffffff);
	{ uint32_t x118 = (x116 + x90);
	{ uint32_t x119 = (x118 >> 0x19);
	{ uint32_t x120 = (x118 & 0x1ffffff);
	out[0] = x117;
	out[1] = x120;
	out[2] = (x119 + x93);
	out[3] = x96;
	out[4] = x99;
	out[5] = x102;
	out[6] = x105;
	out[7] = x108;
	out[8] = x111;
	out[9] = x114;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

static __always_inline void fe_mul121666(fe *h, const fe_loose *f)
{
	fe_mul_121666_impl(h->v, f->v);
}

void curve25519(uint8_t out[static CURVE25519_POINT_SIZE], const uint8_t scalar[static CURVE25519_POINT_SIZE], const uint8_t point[static CURVE25519_POINT_SIZE])
{
	fe x1, x2, z2, x3, z3, tmp0, tmp1;
	fe_loose x2l, z2l, x3l, tmp0l, tmp1l;
	unsigned swap = 0;
	int pos;
	uint8_t e[32];

	memcpy(e, scalar, 32);
	curve25519_normalize_secret(e);

	/* The following implementation was transcribed to Coq and proven to
	 * correspond to unary scalar multiplication in affine coordinates given that
	 * x1 != 0 is the x coordinate of some point on the curve. It was also checked
	 * in Coq that doing a ladderstep with x1 = x3 = 0 gives z2' = z3' = 0, and z2
	 * = z3 = 0 gives z2' = z3' = 0. The statement was quantified over the
	 * underlying field, so it applies to Curve25519 itself and the quadratic
	 * twist of Curve25519. It was not proven in Coq that prime-field arithmetic
	 * correctly simulates extension-field arithmetic on prime-field values.
	 * The decoding of the byte array representation of e was not considered.
	 * Specification of Montgomery curves in affine coordinates:
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Spec/MontgomeryCurve.v#L27>
	 * Proof that these form a group that is isomorphic to a Weierstrass curve:
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/AffineProofs.v#L35>
	 * Coq transcription and correctness proof of the loop (where scalarbits=255):
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L118>
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L278>
	 * preconditions: 0 <= e < 2^255 (not necessarily e < order), fe_invert(0) = 0
	 */
	fe_frombytes(&x1, point);
	fe_1(&x2);
	fe_0(&z2);
	fe_copy(&x3, &x1);
	fe_1(&z3);

	for (pos = 254; pos >= 0; --pos) {
		/* loop invariant as of right before the test, for the case where x1 != 0:
		 *   pos >= -1; if z2 = 0 then x2 is nonzero; if z3 = 0 then x3 is nonzero
		 *   let r := e >> (pos+1) in the following equalities of projective points:
		 *   to_xz (r*P)     === if swap then (x3, z3) else (x2, z2)
		 *   to_xz ((r+1)*P) === if swap then (x2, z2) else (x3, z3)
		 *   x1 is the nonzero x coordinate of the nonzero point (r*P-(r+1)*P)
		 */
		unsigned b = 1 & (e[pos / 8] >> (pos & 7));
		swap ^= b;
		fe_cswap(&x2, &x3, swap);
		fe_cswap(&z2, &z3, swap);
		swap = b;
		/* Coq transcription of ladderstep formula (called from transcribed loop):
		 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L89>
		 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L131>
		 * x1 != 0 <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L217>
		 * x1  = 0 <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L147>
		 */
		fe_sub(&tmp0l, &x3, &z3);
		fe_sub(&tmp1l, &x2, &z2);
		fe_add(&x2l, &x2, &z2);
		fe_add(&z2l, &x3, &z3);
		fe_mul_tll(&z3, &tmp0l, &x2l);
		fe_mul_tll(&z2, &z2l, &tmp1l);
		fe_sq_tl(&tmp0, &tmp1l);
		fe_sq_tl(&tmp1, &x2l);
		fe_add(&x3l, &z3, &z2);
		fe_sub(&z2l, &z3, &z2);
		fe_mul_ttt(&x2, &tmp1, &tmp0);
		fe_sub(&tmp1l, &tmp1, &tmp0);
		fe_sq_tl(&z2, &z2l);
		fe_mul121666(&z3, &tmp1l);
		fe_sq_tl(&x3, &x3l);
		fe_add(&tmp0l, &tmp0, &z3);
		fe_mul_ttt(&z3, &x1, &z2);
		fe_mul_tll(&z2, &tmp1l, &tmp0l);
	}
	/* here pos=-1, so r=e, so to_xz (e*P) === if swap then (x3, z3) else (x2, z2) */
	fe_cswap(&x2, &x3, swap);
	fe_cswap(&z2, &z3, swap);

	fe_invert(&z2, &z2);
	fe_mul_ttt(&x2, &x2, &z2);
	fe_tobytes(out, &x2);
}
#endif

void curve25519_generate_public(uint8_t pub[static CURVE25519_POINT_SIZE], const uint8_t secret[static CURVE25519_POINT_SIZE])
{
	static const uint8_t basepoint[CURVE25519_POINT_SIZE] = { 9 };

	curve25519(pub, secret, basepoint);
}
