/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2016 The fiat-crypto Authors.
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is a machine-generated formally verified implementation of curve25519 DH from:
 * https://github.com/mit-plv/fiat-crypto
 */

#if defined(CONFIG_ARCH_SUPPORTS_INT128) && defined(__SIZEOF_INT128__)
typedef __uint128_t u128;

/* fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[4], represents the integer t[0]+2^51 t[1]+2^102 t[2]+2^153
 * t[3]+2^204 t[4].
 * fe limbs are bounded by 1.125*2^51.
 * Multiplication and carrying produce fe from fe_loose.
 */
typedef struct fe { u64 v[5]; } fe;

/* fe_loose limbs are bounded by 3.375*2^51.
 * Addition and subtraction produce fe_loose from (fe, fe).
 */
typedef struct fe_loose { u64 v[5]; } fe_loose;

static __always_inline void fe_frombytes_impl(u64 h[5], const u8 *s)
{
	// Ignores top bit of s.
	u64 a0 = le64_to_cpup((__force __le64 *)(s));
	u64 a1 = le64_to_cpup((__force __le64 *)(s+8));
	u64 a2 = le64_to_cpup((__force __le64 *)(s+16));
	u64 a3 = le64_to_cpup((__force __le64 *)(s+24));
	// Use 51 bits, 64-51 = 13 left.
	h[0] = a0 & ((1ULL << 51) - 1);
	// (64-51) + 38 = 13 + 38 = 51
	h[1] = (a0 >> 51) | ((a1 & ((1ULL << 38) - 1)) << 13);
	// (64-38) + 25 = 26 + 25 = 51
	h[2] = (a1 >> 38) | ((a2 & ((1ULL << 25) - 1)) << 26);
	// (64-25) + 12 = 39 + 12 = 51
	h[3] = (a2 >> 25) | ((a3 & ((1ULL << 12) - 1)) << 39);
	// (64-12) = 52, ignore top bit
	h[4] = (a3 >> 12) & ((1ULL << 51) - 1);
}

static __always_inline u8 /*bool*/ addcarryx_u51(u8 /*bool*/ c, u64 a, u64 b, u64 *low)
{
	/* This function extracts 51 bits of result and 1 bit of carry (52 total), so
	 *a 64-bit intermediate is sufficient.
	 */
	u64 x = a + b + c;
	*low = x & ((1ULL << 51) - 1);
	return (x >> 51) & 1;
}

static __always_inline u8 /*bool*/ subborrow_u51(u8 /*bool*/ c, u64 a, u64 b, u64 *low)
{
	/* This function extracts 51 bits of result and 1 bit of borrow (52 total), so
	 * a 64-bit intermediate is sufficient.
	 */
	u64 x = a - b - c;
	*low = x & ((1ULL << 51) - 1);
	return x >> 63;
}

static __always_inline u64 cmovznz64(u64 t, u64 z, u64 nz)
{
	/* all set if nonzero, 0 if 0 */
	t = -!!t;
	return (t&nz) | ((~t)&z);
}

static __always_inline void fe_freeze(u64 out[5], const u64 in1[5])
{
	{ const u64 x7 = in1[4];
	{ const u64 x8 = in1[3];
	{ const u64 x6 = in1[2];
	{ const u64 x4 = in1[1];
	{ const u64 x2 = in1[0];
	{ u64 x10; u8/*bool*/ x11 = subborrow_u51(0x0, x2, 0x7ffffffffffed, &x10);
	{ u64 x13; u8/*bool*/ x14 = subborrow_u51(x11, x4, 0x7ffffffffffff, &x13);
	{ u64 x16; u8/*bool*/ x17 = subborrow_u51(x14, x6, 0x7ffffffffffff, &x16);
	{ u64 x19; u8/*bool*/ x20 = subborrow_u51(x17, x8, 0x7ffffffffffff, &x19);
	{ u64 x22; u8/*bool*/ x23 = subborrow_u51(x20, x7, 0x7ffffffffffff, &x22);
	{ u64 x24 = cmovznz64(x23, 0x0, 0xffffffffffffffffL);
	{ u64 x25 = (x24 & 0x7ffffffffffed);
	{ u64 x27; u8/*bool*/ x28 = addcarryx_u51(0x0, x10, x25, &x27);
	{ u64 x29 = (x24 & 0x7ffffffffffff);
	{ u64 x31; u8/*bool*/ x32 = addcarryx_u51(x28, x13, x29, &x31);
	{ u64 x33 = (x24 & 0x7ffffffffffff);
	{ u64 x35; u8/*bool*/ x36 = addcarryx_u51(x32, x16, x33, &x35);
	{ u64 x37 = (x24 & 0x7ffffffffffff);
	{ u64 x39; u8/*bool*/ x40 = addcarryx_u51(x36, x19, x37, &x39);
	{ u64 x41 = (x24 & 0x7ffffffffffff);
	{ u64 x43; addcarryx_u51(x40, x22, x41, &x43);
	out[0] = x27;
	out[1] = x31;
	out[2] = x35;
	out[3] = x39;
	out[4] = x43;
	}}}}}}}}}}}}}}}}}}}}}
}

static __always_inline void fe_tobytes(u8 s[32], const fe *f)
{
	u64 h[5];
	fe_freeze(h, f->v);

	s[0] = h[0] >> 0;
	s[1] = h[0] >> 8;
	s[2] = h[0] >> 16;
	s[3] = h[0] >> 24;
	s[4] = h[0] >> 32;
	s[5] = h[0] >> 40;
	s[6] = (h[0] >> 48) | (h[1] << 3);
	s[7] = h[1] >> 5;
	s[8] = h[1] >> 13;
	s[9] = h[1] >> 21;
	s[10] = h[1] >> 29;
	s[11] = h[1] >> 37;
	s[12] = (h[1] >> 45) | (h[2] << 6);
	s[13] = h[2] >> 2;
	s[14] = h[2] >> 10;
	s[15] = h[2] >> 18;
	s[16] = h[2] >> 26;
	s[17] = h[2] >> 34;
	s[18] = h[2] >> 42;
	s[19] = (h[2] >> 50) | (h[3] << 1);
	s[20] = h[3] >> 7;
	s[21] = h[3] >> 15;
	s[22] = h[3] >> 23;
	s[23] = h[3] >> 31;
	s[24] = h[3] >> 39;
	s[25] = (h[3] >> 47) | (h[4] << 4);
	s[26] = h[4] >> 4;
	s[27] = h[4] >> 12;
	s[28] = h[4] >> 20;
	s[29] = h[4] >> 28;
	s[30] = h[4] >> 36;
	s[31] = h[4] >> 44;
}

static __always_inline void fe_add_impl(u64 out[5], const u64 in1[5], const u64 in2[5])
{
	{ const u64 x10 = in1[4];
	{ const u64 x11 = in1[3];
	{ const u64 x9 = in1[2];
	{ const u64 x7 = in1[1];
	{ const u64 x5 = in1[0];
	{ const u64 x18 = in2[4];
	{ const u64 x19 = in2[3];
	{ const u64 x17 = in2[2];
	{ const u64 x15 = in2[1];
	{ const u64 x13 = in2[0];
	out[0] = (x5 + x13);
	out[1] = (x7 + x15);
	out[2] = (x9 + x17);
	out[3] = (x11 + x19);
	out[4] = (x10 + x18);
	}}}}}}}}}}
}

static __always_inline void fe_sub_impl(u64 out[5], const u64 in1[5], const u64 in2[5])
{
	{ const u64 x10 = in1[4];
	{ const u64 x11 = in1[3];
	{ const u64 x9 = in1[2];
	{ const u64 x7 = in1[1];
	{ const u64 x5 = in1[0];
	{ const u64 x18 = in2[4];
	{ const u64 x19 = in2[3];
	{ const u64 x17 = in2[2];
	{ const u64 x15 = in2[1];
	{ const u64 x13 = in2[0];
	out[0] = ((0xfffffffffffda + x5) - x13);
	out[1] = ((0xffffffffffffe + x7) - x15);
	out[2] = ((0xffffffffffffe + x9) - x17);
	out[3] = ((0xffffffffffffe + x11) - x19);
	out[4] = ((0xffffffffffffe + x10) - x18);
	}}}}}}}}}}
}

static __always_inline void fe_mul_impl(u64 out[5], const u64 in1[5], const u64 in2[5])
{
	{ const u64 x10 = in1[4];
	{ const u64 x11 = in1[3];
	{ const u64 x9 = in1[2];
	{ const u64 x7 = in1[1];
	{ const u64 x5 = in1[0];
	{ const u64 x18 = in2[4];
	{ const u64 x19 = in2[3];
	{ const u64 x17 = in2[2];
	{ const u64 x15 = in2[1];
	{ const u64 x13 = in2[0];
	{ u128 x20 = ((u128)x5 * x13);
	{ u128 x21 = (((u128)x5 * x15) + ((u128)x7 * x13));
	{ u128 x22 = ((((u128)x5 * x17) + ((u128)x9 * x13)) + ((u128)x7 * x15));
	{ u128 x23 = (((((u128)x5 * x19) + ((u128)x11 * x13)) + ((u128)x7 * x17)) + ((u128)x9 * x15));
	{ u128 x24 = ((((((u128)x5 * x18) + ((u128)x10 * x13)) + ((u128)x11 * x15)) + ((u128)x7 * x19)) + ((u128)x9 * x17));
	{ u64 x25 = (x10 * 0x13);
	{ u64 x26 = (x7 * 0x13);
	{ u64 x27 = (x9 * 0x13);
	{ u64 x28 = (x11 * 0x13);
	{ u128 x29 = ((((x20 + ((u128)x25 * x15)) + ((u128)x26 * x18)) + ((u128)x27 * x19)) + ((u128)x28 * x17));
	{ u128 x30 = (((x21 + ((u128)x25 * x17)) + ((u128)x27 * x18)) + ((u128)x28 * x19));
	{ u128 x31 = ((x22 + ((u128)x25 * x19)) + ((u128)x28 * x18));
	{ u128 x32 = (x23 + ((u128)x25 * x18));
	{ u64 x33 = (u64) (x29 >> 0x33);
	{ u64 x34 = ((u64)x29 & 0x7ffffffffffff);
	{ u128 x35 = (x33 + x30);
	{ u64 x36 = (u64) (x35 >> 0x33);
	{ u64 x37 = ((u64)x35 & 0x7ffffffffffff);
	{ u128 x38 = (x36 + x31);
	{ u64 x39 = (u64) (x38 >> 0x33);
	{ u64 x40 = ((u64)x38 & 0x7ffffffffffff);
	{ u128 x41 = (x39 + x32);
	{ u64 x42 = (u64) (x41 >> 0x33);
	{ u64 x43 = ((u64)x41 & 0x7ffffffffffff);
	{ u128 x44 = (x42 + x24);
	{ u64 x45 = (u64) (x44 >> 0x33);
	{ u64 x46 = ((u64)x44 & 0x7ffffffffffff);
	{ u64 x47 = (x34 + (0x13 * x45));
	{ u64 x48 = (x47 >> 0x33);
	{ u64 x49 = (x47 & 0x7ffffffffffff);
	{ u64 x50 = (x48 + x37);
	{ u64 x51 = (x50 >> 0x33);
	{ u64 x52 = (x50 & 0x7ffffffffffff);
	out[0] = x49;
	out[1] = x52;
	out[2] = (x51 + x40);
	out[3] = x43;
	out[4] = x46;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

static __always_inline void fe_sqr_impl(u64 out[5], const u64 in1[5])
{
	{ const u64 x7 = in1[4];
	{ const u64 x8 = in1[3];
	{ const u64 x6 = in1[2];
	{ const u64 x4 = in1[1];
	{ const u64 x2 = in1[0];
	{ u64 x9 = (x2 * 0x2);
	{ u64 x10 = (x4 * 0x2);
	{ u64 x11 = ((x6 * 0x2) * 0x13);
	{ u64 x12 = (x7 * 0x13);
	{ u64 x13 = (x12 * 0x2);
	{ u128 x14 = ((((u128)x2 * x2) + ((u128)x13 * x4)) + ((u128)x11 * x8));
	{ u128 x15 = ((((u128)x9 * x4) + ((u128)x13 * x6)) + ((u128)x8 * (x8 * 0x13)));
	{ u128 x16 = ((((u128)x9 * x6) + ((u128)x4 * x4)) + ((u128)x13 * x8));
	{ u128 x17 = ((((u128)x9 * x8) + ((u128)x10 * x6)) + ((u128)x7 * x12));
	{ u128 x18 = ((((u128)x9 * x7) + ((u128)x10 * x8)) + ((u128)x6 * x6));
	{ u64 x19 = (u64) (x14 >> 0x33);
	{ u64 x20 = ((u64)x14 & 0x7ffffffffffff);
	{ u128 x21 = (x19 + x15);
	{ u64 x22 = (u64) (x21 >> 0x33);
	{ u64 x23 = ((u64)x21 & 0x7ffffffffffff);
	{ u128 x24 = (x22 + x16);
	{ u64 x25 = (u64) (x24 >> 0x33);
	{ u64 x26 = ((u64)x24 & 0x7ffffffffffff);
	{ u128 x27 = (x25 + x17);
	{ u64 x28 = (u64) (x27 >> 0x33);
	{ u64 x29 = ((u64)x27 & 0x7ffffffffffff);
	{ u128 x30 = (x28 + x18);
	{ u64 x31 = (u64) (x30 >> 0x33);
	{ u64 x32 = ((u64)x30 & 0x7ffffffffffff);
	{ u64 x33 = (x20 + (0x13 * x31));
	{ u64 x34 = (x33 >> 0x33);
	{ u64 x35 = (x33 & 0x7ffffffffffff);
	{ u64 x36 = (x34 + x23);
	{ u64 x37 = (x36 >> 0x33);
	{ u64 x38 = (x36 & 0x7ffffffffffff);
	out[0] = x35;
	out[1] = x38;
	out[2] = (x37 + x26);
	out[3] = x29;
	out[4] = x32;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

/* Replace (f,g) with (g,f) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}
 */
static __always_inline void fe_cswap(fe *f, fe *g, u64 b)
{
	unsigned i;
	b = 0-b;
	for (i = 0; i < 5; i++) {
		u64 x = f->v[i] ^ g->v[i];
		x &= b;
		f->v[i] ^= x;
		g->v[i] ^= x;
	}
}

/* NOTE: based on fiat-crypto fe_mul, edited for in2=121666, 0, 0.*/
static __always_inline void fe_mul_121666_impl(u64 out[5], const u64 in1[5])
{
	{ const u64 x10 = in1[4];
	{ const u64 x11 = in1[3];
	{ const u64 x9 = in1[2];
	{ const u64 x7 = in1[1];
	{ const u64 x5 = in1[0];
	{ const u64 x18 = 0;
	{ const u64 x19 = 0;
	{ const u64 x17 = 0;
	{ const u64 x15 = 0;
	{ const u64 x13 = 121666;
	{ u128 x20 = ((u128)x5 * x13);
	{ u128 x21 = (((u128)x5 * x15) + ((u128)x7 * x13));
	{ u128 x22 = ((((u128)x5 * x17) + ((u128)x9 * x13)) + ((u128)x7 * x15));
	{ u128 x23 = (((((u128)x5 * x19) + ((u128)x11 * x13)) + ((u128)x7 * x17)) + ((u128)x9 * x15));
	{ u128 x24 = ((((((u128)x5 * x18) + ((u128)x10 * x13)) + ((u128)x11 * x15)) + ((u128)x7 * x19)) + ((u128)x9 * x17));
	{ u64 x25 = (x10 * 0x13);
	{ u64 x26 = (x7 * 0x13);
	{ u64 x27 = (x9 * 0x13);
	{ u64 x28 = (x11 * 0x13);
	{ u128 x29 = ((((x20 + ((u128)x25 * x15)) + ((u128)x26 * x18)) + ((u128)x27 * x19)) + ((u128)x28 * x17));
	{ u128 x30 = (((x21 + ((u128)x25 * x17)) + ((u128)x27 * x18)) + ((u128)x28 * x19));
	{ u128 x31 = ((x22 + ((u128)x25 * x19)) + ((u128)x28 * x18));
	{ u128 x32 = (x23 + ((u128)x25 * x18));
	{ u64 x33 = (u64) (x29 >> 0x33);
	{ u64 x34 = ((u64)x29 & 0x7ffffffffffff);
	{ u128 x35 = (x33 + x30);
	{ u64 x36 = (u64) (x35 >> 0x33);
	{ u64 x37 = ((u64)x35 & 0x7ffffffffffff);
	{ u128 x38 = (x36 + x31);
	{ u64 x39 = (u64) (x38 >> 0x33);
	{ u64 x40 = ((u64)x38 & 0x7ffffffffffff);
	{ u128 x41 = (x39 + x32);
	{ u64 x42 = (u64) (x41 >> 0x33);
	{ u64 x43 = ((u64)x41 & 0x7ffffffffffff);
	{ u128 x44 = (x42 + x24);
	{ u64 x45 = (u64) (x44 >> 0x33);
	{ u64 x46 = ((u64)x44 & 0x7ffffffffffff);
	{ u64 x47 = (x34 + (0x13 * x45));
	{ u64 x48 = (x47 >> 0x33);
	{ u64 x49 = (x47 & 0x7ffffffffffff);
	{ u64 x50 = (x48 + x37);
	{ u64 x51 = (x50 >> 0x33);
	{ u64 x52 = (x50 & 0x7ffffffffffff);
	out[0] = x49;
	out[1] = x52;
	out[2] = (x51 + x40);
	out[3] = x43;
	out[4] = x46;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}
#else
/* fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9].
 * fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
 * Multiplication and carrying produce fe from fe_loose.
 */
typedef struct fe { u32 v[10]; } fe;

/* fe_loose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc.
 * Addition and subtraction produce fe_loose from (fe, fe).
 */
typedef struct fe_loose { u32 v[10]; } fe_loose;

static __always_inline void fe_frombytes_impl(u32 h[10], const u8 *s)
{
	/* Ignores top bit of s. */
	u32 a0 = le32_to_cpup((__force __le32 *)(s));
	u32 a1 = le32_to_cpup((__force __le32 *)(s+4));
	u32 a2 = le32_to_cpup((__force __le32 *)(s+8));
	u32 a3 = le32_to_cpup((__force __le32 *)(s+12));
	u32 a4 = le32_to_cpup((__force __le32 *)(s+16));
	u32 a5 = le32_to_cpup((__force __le32 *)(s+20));
	u32 a6 = le32_to_cpup((__force __le32 *)(s+24));
	u32 a7 = le32_to_cpup((__force __le32 *)(s+28));
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

static __always_inline u8 /*bool*/ addcarryx_u25(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 25 bits of result and 1 bit of carry (26 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	u32 x = a + b + c;
	*low = x & ((1 << 25) - 1);
	return (x >> 25) & 1;
}

static __always_inline u8 /*bool*/ addcarryx_u26(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 26 bits of result and 1 bit of carry (27 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	u32 x = a + b + c;
	*low = x & ((1 << 26) - 1);
	return (x >> 26) & 1;
}

static __always_inline u8 /*bool*/ subborrow_u25(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 25 bits of result and 1 bit of borrow (26 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	u32 x = a - b - c;
	*low = x & ((1 << 25) - 1);
	return x >> 31;
}

static __always_inline u8 /*bool*/ subborrow_u26(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 26 bits of result and 1 bit of borrow (27 total), so
	 * a 32-bit intermediate is sufficient.
	 */
	u32 x = a - b - c;
	*low = x & ((1 << 26) - 1);
	return x >> 31;
}

static __always_inline u32 cmovznz32(u32 t, u32 z, u32 nz)
{
	t = -!!t; /* all set if nonzero, 0 if 0 */
	return (t&nz) | ((~t)&z);
}

static __always_inline void fe_freeze(u32 out[10], const u32 in1[10])
{
	{ const u32 x17 = in1[9];
	{ const u32 x18 = in1[8];
	{ const u32 x16 = in1[7];
	{ const u32 x14 = in1[6];
	{ const u32 x12 = in1[5];
	{ const u32 x10 = in1[4];
	{ const u32 x8 = in1[3];
	{ const u32 x6 = in1[2];
	{ const u32 x4 = in1[1];
	{ const u32 x2 = in1[0];
	{ u32 x20; u8/*bool*/ x21 = subborrow_u26(0x0, x2, 0x3ffffed, &x20);
	{ u32 x23; u8/*bool*/ x24 = subborrow_u25(x21, x4, 0x1ffffff, &x23);
	{ u32 x26; u8/*bool*/ x27 = subborrow_u26(x24, x6, 0x3ffffff, &x26);
	{ u32 x29; u8/*bool*/ x30 = subborrow_u25(x27, x8, 0x1ffffff, &x29);
	{ u32 x32; u8/*bool*/ x33 = subborrow_u26(x30, x10, 0x3ffffff, &x32);
	{ u32 x35; u8/*bool*/ x36 = subborrow_u25(x33, x12, 0x1ffffff, &x35);
	{ u32 x38; u8/*bool*/ x39 = subborrow_u26(x36, x14, 0x3ffffff, &x38);
	{ u32 x41; u8/*bool*/ x42 = subborrow_u25(x39, x16, 0x1ffffff, &x41);
	{ u32 x44; u8/*bool*/ x45 = subborrow_u26(x42, x18, 0x3ffffff, &x44);
	{ u32 x47; u8/*bool*/ x48 = subborrow_u25(x45, x17, 0x1ffffff, &x47);
	{ u32 x49 = cmovznz32(x48, 0x0, 0xffffffff);
	{ u32 x50 = (x49 & 0x3ffffed);
	{ u32 x52; u8/*bool*/ x53 = addcarryx_u26(0x0, x20, x50, &x52);
	{ u32 x54 = (x49 & 0x1ffffff);
	{ u32 x56; u8/*bool*/ x57 = addcarryx_u25(x53, x23, x54, &x56);
	{ u32 x58 = (x49 & 0x3ffffff);
	{ u32 x60; u8/*bool*/ x61 = addcarryx_u26(x57, x26, x58, &x60);
	{ u32 x62 = (x49 & 0x1ffffff);
	{ u32 x64; u8/*bool*/ x65 = addcarryx_u25(x61, x29, x62, &x64);
	{ u32 x66 = (x49 & 0x3ffffff);
	{ u32 x68; u8/*bool*/ x69 = addcarryx_u26(x65, x32, x66, &x68);
	{ u32 x70 = (x49 & 0x1ffffff);
	{ u32 x72; u8/*bool*/ x73 = addcarryx_u25(x69, x35, x70, &x72);
	{ u32 x74 = (x49 & 0x3ffffff);
	{ u32 x76; u8/*bool*/ x77 = addcarryx_u26(x73, x38, x74, &x76);
	{ u32 x78 = (x49 & 0x1ffffff);
	{ u32 x80; u8/*bool*/ x81 = addcarryx_u25(x77, x41, x78, &x80);
	{ u32 x82 = (x49 & 0x3ffffff);
	{ u32 x84; u8/*bool*/ x85 = addcarryx_u26(x81, x44, x82, &x84);
	{ u32 x86 = (x49 & 0x1ffffff);
	{ u32 x88; addcarryx_u25(x85, x47, x86, &x88);
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

static __always_inline void fe_tobytes(u8 s[32], const fe *f)
{
	u32 h[10];
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

static void fe_add_impl(u32 out[10], const u32 in1[10], const u32 in2[10])
{
	{ const u32 x20 = in1[9];
	{ const u32 x21 = in1[8];
	{ const u32 x19 = in1[7];
	{ const u32 x17 = in1[6];
	{ const u32 x15 = in1[5];
	{ const u32 x13 = in1[4];
	{ const u32 x11 = in1[3];
	{ const u32 x9 = in1[2];
	{ const u32 x7 = in1[1];
	{ const u32 x5 = in1[0];
	{ const u32 x38 = in2[9];
	{ const u32 x39 = in2[8];
	{ const u32 x37 = in2[7];
	{ const u32 x35 = in2[6];
	{ const u32 x33 = in2[5];
	{ const u32 x31 = in2[4];
	{ const u32 x29 = in2[3];
	{ const u32 x27 = in2[2];
	{ const u32 x25 = in2[1];
	{ const u32 x23 = in2[0];
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

static void fe_sub_impl(u32 out[10], const u32 in1[10], const u32 in2[10])
{
	{ const u32 x20 = in1[9];
	{ const u32 x21 = in1[8];
	{ const u32 x19 = in1[7];
	{ const u32 x17 = in1[6];
	{ const u32 x15 = in1[5];
	{ const u32 x13 = in1[4];
	{ const u32 x11 = in1[3];
	{ const u32 x9 = in1[2];
	{ const u32 x7 = in1[1];
	{ const u32 x5 = in1[0];
	{ const u32 x38 = in2[9];
	{ const u32 x39 = in2[8];
	{ const u32 x37 = in2[7];
	{ const u32 x35 = in2[6];
	{ const u32 x33 = in2[5];
	{ const u32 x31 = in2[4];
	{ const u32 x29 = in2[3];
	{ const u32 x27 = in2[2];
	{ const u32 x25 = in2[1];
	{ const u32 x23 = in2[0];
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

static void fe_mul_impl(u32 out[10], const u32 in1[10], const u32 in2[10])
{
	{ const u32 x20 = in1[9];
	{ const u32 x21 = in1[8];
	{ const u32 x19 = in1[7];
	{ const u32 x17 = in1[6];
	{ const u32 x15 = in1[5];
	{ const u32 x13 = in1[4];
	{ const u32 x11 = in1[3];
	{ const u32 x9 = in1[2];
	{ const u32 x7 = in1[1];
	{ const u32 x5 = in1[0];
	{ const u32 x38 = in2[9];
	{ const u32 x39 = in2[8];
	{ const u32 x37 = in2[7];
	{ const u32 x35 = in2[6];
	{ const u32 x33 = in2[5];
	{ const u32 x31 = in2[4];
	{ const u32 x29 = in2[3];
	{ const u32 x27 = in2[2];
	{ const u32 x25 = in2[1];
	{ const u32 x23 = in2[0];
	{ u64 x40 = ((u64)x23 * x5);
	{ u64 x41 = (((u64)x23 * x7) + ((u64)x25 * x5));
	{ u64 x42 = ((((u64)(0x2 * x25) * x7) + ((u64)x23 * x9)) + ((u64)x27 * x5));
	{ u64 x43 = (((((u64)x25 * x9) + ((u64)x27 * x7)) + ((u64)x23 * x11)) + ((u64)x29 * x5));
	{ u64 x44 = (((((u64)x27 * x9) + (0x2 * (((u64)x25 * x11) + ((u64)x29 * x7)))) + ((u64)x23 * x13)) + ((u64)x31 * x5));
	{ u64 x45 = (((((((u64)x27 * x11) + ((u64)x29 * x9)) + ((u64)x25 * x13)) + ((u64)x31 * x7)) + ((u64)x23 * x15)) + ((u64)x33 * x5));
	{ u64 x46 = (((((0x2 * ((((u64)x29 * x11) + ((u64)x25 * x15)) + ((u64)x33 * x7))) + ((u64)x27 * x13)) + ((u64)x31 * x9)) + ((u64)x23 * x17)) + ((u64)x35 * x5));
	{ u64 x47 = (((((((((u64)x29 * x13) + ((u64)x31 * x11)) + ((u64)x27 * x15)) + ((u64)x33 * x9)) + ((u64)x25 * x17)) + ((u64)x35 * x7)) + ((u64)x23 * x19)) + ((u64)x37 * x5));
	{ u64 x48 = (((((((u64)x31 * x13) + (0x2 * (((((u64)x29 * x15) + ((u64)x33 * x11)) + ((u64)x25 * x19)) + ((u64)x37 * x7)))) + ((u64)x27 * x17)) + ((u64)x35 * x9)) + ((u64)x23 * x21)) + ((u64)x39 * x5));
	{ u64 x49 = (((((((((((u64)x31 * x15) + ((u64)x33 * x13)) + ((u64)x29 * x17)) + ((u64)x35 * x11)) + ((u64)x27 * x19)) + ((u64)x37 * x9)) + ((u64)x25 * x21)) + ((u64)x39 * x7)) + ((u64)x23 * x20)) + ((u64)x38 * x5));
	{ u64 x50 = (((((0x2 * ((((((u64)x33 * x15) + ((u64)x29 * x19)) + ((u64)x37 * x11)) + ((u64)x25 * x20)) + ((u64)x38 * x7))) + ((u64)x31 * x17)) + ((u64)x35 * x13)) + ((u64)x27 * x21)) + ((u64)x39 * x9));
	{ u64 x51 = (((((((((u64)x33 * x17) + ((u64)x35 * x15)) + ((u64)x31 * x19)) + ((u64)x37 * x13)) + ((u64)x29 * x21)) + ((u64)x39 * x11)) + ((u64)x27 * x20)) + ((u64)x38 * x9));
	{ u64 x52 = (((((u64)x35 * x17) + (0x2 * (((((u64)x33 * x19) + ((u64)x37 * x15)) + ((u64)x29 * x20)) + ((u64)x38 * x11)))) + ((u64)x31 * x21)) + ((u64)x39 * x13));
	{ u64 x53 = (((((((u64)x35 * x19) + ((u64)x37 * x17)) + ((u64)x33 * x21)) + ((u64)x39 * x15)) + ((u64)x31 * x20)) + ((u64)x38 * x13));
	{ u64 x54 = (((0x2 * ((((u64)x37 * x19) + ((u64)x33 * x20)) + ((u64)x38 * x15))) + ((u64)x35 * x21)) + ((u64)x39 * x17));
	{ u64 x55 = (((((u64)x37 * x21) + ((u64)x39 * x19)) + ((u64)x35 * x20)) + ((u64)x38 * x17));
	{ u64 x56 = (((u64)x39 * x21) + (0x2 * (((u64)x37 * x20) + ((u64)x38 * x19))));
	{ u64 x57 = (((u64)x39 * x20) + ((u64)x38 * x21));
	{ u64 x58 = ((u64)(0x2 * x38) * x20);
	{ u64 x59 = (x48 + (x58 << 0x4));
	{ u64 x60 = (x59 + (x58 << 0x1));
	{ u64 x61 = (x60 + x58);
	{ u64 x62 = (x47 + (x57 << 0x4));
	{ u64 x63 = (x62 + (x57 << 0x1));
	{ u64 x64 = (x63 + x57);
	{ u64 x65 = (x46 + (x56 << 0x4));
	{ u64 x66 = (x65 + (x56 << 0x1));
	{ u64 x67 = (x66 + x56);
	{ u64 x68 = (x45 + (x55 << 0x4));
	{ u64 x69 = (x68 + (x55 << 0x1));
	{ u64 x70 = (x69 + x55);
	{ u64 x71 = (x44 + (x54 << 0x4));
	{ u64 x72 = (x71 + (x54 << 0x1));
	{ u64 x73 = (x72 + x54);
	{ u64 x74 = (x43 + (x53 << 0x4));
	{ u64 x75 = (x74 + (x53 << 0x1));
	{ u64 x76 = (x75 + x53);
	{ u64 x77 = (x42 + (x52 << 0x4));
	{ u64 x78 = (x77 + (x52 << 0x1));
	{ u64 x79 = (x78 + x52);
	{ u64 x80 = (x41 + (x51 << 0x4));
	{ u64 x81 = (x80 + (x51 << 0x1));
	{ u64 x82 = (x81 + x51);
	{ u64 x83 = (x40 + (x50 << 0x4));
	{ u64 x84 = (x83 + (x50 << 0x1));
	{ u64 x85 = (x84 + x50);
	{ u64 x86 = (x85 >> 0x1a);
	{ u32 x87 = ((u32)x85 & 0x3ffffff);
	{ u64 x88 = (x86 + x82);
	{ u64 x89 = (x88 >> 0x19);
	{ u32 x90 = ((u32)x88 & 0x1ffffff);
	{ u64 x91 = (x89 + x79);
	{ u64 x92 = (x91 >> 0x1a);
	{ u32 x93 = ((u32)x91 & 0x3ffffff);
	{ u64 x94 = (x92 + x76);
	{ u64 x95 = (x94 >> 0x19);
	{ u32 x96 = ((u32)x94 & 0x1ffffff);
	{ u64 x97 = (x95 + x73);
	{ u64 x98 = (x97 >> 0x1a);
	{ u32 x99 = ((u32)x97 & 0x3ffffff);
	{ u64 x100 = (x98 + x70);
	{ u64 x101 = (x100 >> 0x19);
	{ u32 x102 = ((u32)x100 & 0x1ffffff);
	{ u64 x103 = (x101 + x67);
	{ u64 x104 = (x103 >> 0x1a);
	{ u32 x105 = ((u32)x103 & 0x3ffffff);
	{ u64 x106 = (x104 + x64);
	{ u64 x107 = (x106 >> 0x19);
	{ u32 x108 = ((u32)x106 & 0x1ffffff);
	{ u64 x109 = (x107 + x61);
	{ u64 x110 = (x109 >> 0x1a);
	{ u32 x111 = ((u32)x109 & 0x3ffffff);
	{ u64 x112 = (x110 + x49);
	{ u64 x113 = (x112 >> 0x19);
	{ u32 x114 = ((u32)x112 & 0x1ffffff);
	{ u64 x115 = (x87 + (0x13 * x113));
	{ u32 x116 = (u32) (x115 >> 0x1a);
	{ u32 x117 = ((u32)x115 & 0x3ffffff);
	{ u32 x118 = (x116 + x90);
	{ u32 x119 = (x118 >> 0x19);
	{ u32 x120 = (x118 & 0x1ffffff);
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

static void fe_sqr_impl(u32 out[10], const u32 in1[10])
{
	{ const u32 x17 = in1[9];
	{ const u32 x18 = in1[8];
	{ const u32 x16 = in1[7];
	{ const u32 x14 = in1[6];
	{ const u32 x12 = in1[5];
	{ const u32 x10 = in1[4];
	{ const u32 x8 = in1[3];
	{ const u32 x6 = in1[2];
	{ const u32 x4 = in1[1];
	{ const u32 x2 = in1[0];
	{ u64 x19 = ((u64)x2 * x2);
	{ u64 x20 = ((u64)(0x2 * x2) * x4);
	{ u64 x21 = (0x2 * (((u64)x4 * x4) + ((u64)x2 * x6)));
	{ u64 x22 = (0x2 * (((u64)x4 * x6) + ((u64)x2 * x8)));
	{ u64 x23 = ((((u64)x6 * x6) + ((u64)(0x4 * x4) * x8)) + ((u64)(0x2 * x2) * x10));
	{ u64 x24 = (0x2 * ((((u64)x6 * x8) + ((u64)x4 * x10)) + ((u64)x2 * x12)));
	{ u64 x25 = (0x2 * (((((u64)x8 * x8) + ((u64)x6 * x10)) + ((u64)x2 * x14)) + ((u64)(0x2 * x4) * x12)));
	{ u64 x26 = (0x2 * (((((u64)x8 * x10) + ((u64)x6 * x12)) + ((u64)x4 * x14)) + ((u64)x2 * x16)));
	{ u64 x27 = (((u64)x10 * x10) + (0x2 * ((((u64)x6 * x14) + ((u64)x2 * x18)) + (0x2 * (((u64)x4 * x16) + ((u64)x8 * x12))))));
	{ u64 x28 = (0x2 * ((((((u64)x10 * x12) + ((u64)x8 * x14)) + ((u64)x6 * x16)) + ((u64)x4 * x18)) + ((u64)x2 * x17)));
	{ u64 x29 = (0x2 * (((((u64)x12 * x12) + ((u64)x10 * x14)) + ((u64)x6 * x18)) + (0x2 * (((u64)x8 * x16) + ((u64)x4 * x17)))));
	{ u64 x30 = (0x2 * (((((u64)x12 * x14) + ((u64)x10 * x16)) + ((u64)x8 * x18)) + ((u64)x6 * x17)));
	{ u64 x31 = (((u64)x14 * x14) + (0x2 * (((u64)x10 * x18) + (0x2 * (((u64)x12 * x16) + ((u64)x8 * x17))))));
	{ u64 x32 = (0x2 * ((((u64)x14 * x16) + ((u64)x12 * x18)) + ((u64)x10 * x17)));
	{ u64 x33 = (0x2 * ((((u64)x16 * x16) + ((u64)x14 * x18)) + ((u64)(0x2 * x12) * x17)));
	{ u64 x34 = (0x2 * (((u64)x16 * x18) + ((u64)x14 * x17)));
	{ u64 x35 = (((u64)x18 * x18) + ((u64)(0x4 * x16) * x17));
	{ u64 x36 = ((u64)(0x2 * x18) * x17);
	{ u64 x37 = ((u64)(0x2 * x17) * x17);
	{ u64 x38 = (x27 + (x37 << 0x4));
	{ u64 x39 = (x38 + (x37 << 0x1));
	{ u64 x40 = (x39 + x37);
	{ u64 x41 = (x26 + (x36 << 0x4));
	{ u64 x42 = (x41 + (x36 << 0x1));
	{ u64 x43 = (x42 + x36);
	{ u64 x44 = (x25 + (x35 << 0x4));
	{ u64 x45 = (x44 + (x35 << 0x1));
	{ u64 x46 = (x45 + x35);
	{ u64 x47 = (x24 + (x34 << 0x4));
	{ u64 x48 = (x47 + (x34 << 0x1));
	{ u64 x49 = (x48 + x34);
	{ u64 x50 = (x23 + (x33 << 0x4));
	{ u64 x51 = (x50 + (x33 << 0x1));
	{ u64 x52 = (x51 + x33);
	{ u64 x53 = (x22 + (x32 << 0x4));
	{ u64 x54 = (x53 + (x32 << 0x1));
	{ u64 x55 = (x54 + x32);
	{ u64 x56 = (x21 + (x31 << 0x4));
	{ u64 x57 = (x56 + (x31 << 0x1));
	{ u64 x58 = (x57 + x31);
	{ u64 x59 = (x20 + (x30 << 0x4));
	{ u64 x60 = (x59 + (x30 << 0x1));
	{ u64 x61 = (x60 + x30);
	{ u64 x62 = (x19 + (x29 << 0x4));
	{ u64 x63 = (x62 + (x29 << 0x1));
	{ u64 x64 = (x63 + x29);
	{ u64 x65 = (x64 >> 0x1a);
	{ u32 x66 = ((u32)x64 & 0x3ffffff);
	{ u64 x67 = (x65 + x61);
	{ u64 x68 = (x67 >> 0x19);
	{ u32 x69 = ((u32)x67 & 0x1ffffff);
	{ u64 x70 = (x68 + x58);
	{ u64 x71 = (x70 >> 0x1a);
	{ u32 x72 = ((u32)x70 & 0x3ffffff);
	{ u64 x73 = (x71 + x55);
	{ u64 x74 = (x73 >> 0x19);
	{ u32 x75 = ((u32)x73 & 0x1ffffff);
	{ u64 x76 = (x74 + x52);
	{ u64 x77 = (x76 >> 0x1a);
	{ u32 x78 = ((u32)x76 & 0x3ffffff);
	{ u64 x79 = (x77 + x49);
	{ u64 x80 = (x79 >> 0x19);
	{ u32 x81 = ((u32)x79 & 0x1ffffff);
	{ u64 x82 = (x80 + x46);
	{ u64 x83 = (x82 >> 0x1a);
	{ u32 x84 = ((u32)x82 & 0x3ffffff);
	{ u64 x85 = (x83 + x43);
	{ u64 x86 = (x85 >> 0x19);
	{ u32 x87 = ((u32)x85 & 0x1ffffff);
	{ u64 x88 = (x86 + x40);
	{ u64 x89 = (x88 >> 0x1a);
	{ u32 x90 = ((u32)x88 & 0x3ffffff);
	{ u64 x91 = (x89 + x28);
	{ u64 x92 = (x91 >> 0x19);
	{ u32 x93 = ((u32)x91 & 0x1ffffff);
	{ u64 x94 = (x66 + (0x13 * x92));
	{ u32 x95 = (u32) (x94 >> 0x1a);
	{ u32 x96 = ((u32)x94 & 0x3ffffff);
	{ u32 x97 = (x95 + x69);
	{ u32 x98 = (x97 >> 0x19);
	{ u32 x99 = (x97 & 0x1ffffff);
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
		u32 x = f->v[i] ^ g->v[i];
		x &= b;
		f->v[i] ^= x;
		g->v[i] ^= x;
	}
}

/* NOTE: based on fiat-crypto fe_mul, edited for in2=121666, 0, 0.*/
static __always_inline void fe_mul_121666_impl(u32 out[10], const u32 in1[10])
{
	{ const u32 x20 = in1[9];
	{ const u32 x21 = in1[8];
	{ const u32 x19 = in1[7];
	{ const u32 x17 = in1[6];
	{ const u32 x15 = in1[5];
	{ const u32 x13 = in1[4];
	{ const u32 x11 = in1[3];
	{ const u32 x9 = in1[2];
	{ const u32 x7 = in1[1];
	{ const u32 x5 = in1[0];
	{ const u32 x38 = 0;
	{ const u32 x39 = 0;
	{ const u32 x37 = 0;
	{ const u32 x35 = 0;
	{ const u32 x33 = 0;
	{ const u32 x31 = 0;
	{ const u32 x29 = 0;
	{ const u32 x27 = 0;
	{ const u32 x25 = 0;
	{ const u32 x23 = 121666;
	{ u64 x40 = ((u64)x23 * x5);
	{ u64 x41 = (((u64)x23 * x7) + ((u64)x25 * x5));
	{ u64 x42 = ((((u64)(0x2 * x25) * x7) + ((u64)x23 * x9)) + ((u64)x27 * x5));
	{ u64 x43 = (((((u64)x25 * x9) + ((u64)x27 * x7)) + ((u64)x23 * x11)) + ((u64)x29 * x5));
	{ u64 x44 = (((((u64)x27 * x9) + (0x2 * (((u64)x25 * x11) + ((u64)x29 * x7)))) + ((u64)x23 * x13)) + ((u64)x31 * x5));
	{ u64 x45 = (((((((u64)x27 * x11) + ((u64)x29 * x9)) + ((u64)x25 * x13)) + ((u64)x31 * x7)) + ((u64)x23 * x15)) + ((u64)x33 * x5));
	{ u64 x46 = (((((0x2 * ((((u64)x29 * x11) + ((u64)x25 * x15)) + ((u64)x33 * x7))) + ((u64)x27 * x13)) + ((u64)x31 * x9)) + ((u64)x23 * x17)) + ((u64)x35 * x5));
	{ u64 x47 = (((((((((u64)x29 * x13) + ((u64)x31 * x11)) + ((u64)x27 * x15)) + ((u64)x33 * x9)) + ((u64)x25 * x17)) + ((u64)x35 * x7)) + ((u64)x23 * x19)) + ((u64)x37 * x5));
	{ u64 x48 = (((((((u64)x31 * x13) + (0x2 * (((((u64)x29 * x15) + ((u64)x33 * x11)) + ((u64)x25 * x19)) + ((u64)x37 * x7)))) + ((u64)x27 * x17)) + ((u64)x35 * x9)) + ((u64)x23 * x21)) + ((u64)x39 * x5));
	{ u64 x49 = (((((((((((u64)x31 * x15) + ((u64)x33 * x13)) + ((u64)x29 * x17)) + ((u64)x35 * x11)) + ((u64)x27 * x19)) + ((u64)x37 * x9)) + ((u64)x25 * x21)) + ((u64)x39 * x7)) + ((u64)x23 * x20)) + ((u64)x38 * x5));
	{ u64 x50 = (((((0x2 * ((((((u64)x33 * x15) + ((u64)x29 * x19)) + ((u64)x37 * x11)) + ((u64)x25 * x20)) + ((u64)x38 * x7))) + ((u64)x31 * x17)) + ((u64)x35 * x13)) + ((u64)x27 * x21)) + ((u64)x39 * x9));
	{ u64 x51 = (((((((((u64)x33 * x17) + ((u64)x35 * x15)) + ((u64)x31 * x19)) + ((u64)x37 * x13)) + ((u64)x29 * x21)) + ((u64)x39 * x11)) + ((u64)x27 * x20)) + ((u64)x38 * x9));
	{ u64 x52 = (((((u64)x35 * x17) + (0x2 * (((((u64)x33 * x19) + ((u64)x37 * x15)) + ((u64)x29 * x20)) + ((u64)x38 * x11)))) + ((u64)x31 * x21)) + ((u64)x39 * x13));
	{ u64 x53 = (((((((u64)x35 * x19) + ((u64)x37 * x17)) + ((u64)x33 * x21)) + ((u64)x39 * x15)) + ((u64)x31 * x20)) + ((u64)x38 * x13));
	{ u64 x54 = (((0x2 * ((((u64)x37 * x19) + ((u64)x33 * x20)) + ((u64)x38 * x15))) + ((u64)x35 * x21)) + ((u64)x39 * x17));
	{ u64 x55 = (((((u64)x37 * x21) + ((u64)x39 * x19)) + ((u64)x35 * x20)) + ((u64)x38 * x17));
	{ u64 x56 = (((u64)x39 * x21) + (0x2 * (((u64)x37 * x20) + ((u64)x38 * x19))));
	{ u64 x57 = (((u64)x39 * x20) + ((u64)x38 * x21));
	{ u64 x58 = ((u64)(0x2 * x38) * x20);
	{ u64 x59 = (x48 + (x58 << 0x4));
	{ u64 x60 = (x59 + (x58 << 0x1));
	{ u64 x61 = (x60 + x58);
	{ u64 x62 = (x47 + (x57 << 0x4));
	{ u64 x63 = (x62 + (x57 << 0x1));
	{ u64 x64 = (x63 + x57);
	{ u64 x65 = (x46 + (x56 << 0x4));
	{ u64 x66 = (x65 + (x56 << 0x1));
	{ u64 x67 = (x66 + x56);
	{ u64 x68 = (x45 + (x55 << 0x4));
	{ u64 x69 = (x68 + (x55 << 0x1));
	{ u64 x70 = (x69 + x55);
	{ u64 x71 = (x44 + (x54 << 0x4));
	{ u64 x72 = (x71 + (x54 << 0x1));
	{ u64 x73 = (x72 + x54);
	{ u64 x74 = (x43 + (x53 << 0x4));
	{ u64 x75 = (x74 + (x53 << 0x1));
	{ u64 x76 = (x75 + x53);
	{ u64 x77 = (x42 + (x52 << 0x4));
	{ u64 x78 = (x77 + (x52 << 0x1));
	{ u64 x79 = (x78 + x52);
	{ u64 x80 = (x41 + (x51 << 0x4));
	{ u64 x81 = (x80 + (x51 << 0x1));
	{ u64 x82 = (x81 + x51);
	{ u64 x83 = (x40 + (x50 << 0x4));
	{ u64 x84 = (x83 + (x50 << 0x1));
	{ u64 x85 = (x84 + x50);
	{ u64 x86 = (x85 >> 0x1a);
	{ u32 x87 = ((u32)x85 & 0x3ffffff);
	{ u64 x88 = (x86 + x82);
	{ u64 x89 = (x88 >> 0x19);
	{ u32 x90 = ((u32)x88 & 0x1ffffff);
	{ u64 x91 = (x89 + x79);
	{ u64 x92 = (x91 >> 0x1a);
	{ u32 x93 = ((u32)x91 & 0x3ffffff);
	{ u64 x94 = (x92 + x76);
	{ u64 x95 = (x94 >> 0x19);
	{ u32 x96 = ((u32)x94 & 0x1ffffff);
	{ u64 x97 = (x95 + x73);
	{ u64 x98 = (x97 >> 0x1a);
	{ u32 x99 = ((u32)x97 & 0x3ffffff);
	{ u64 x100 = (x98 + x70);
	{ u64 x101 = (x100 >> 0x19);
	{ u32 x102 = ((u32)x100 & 0x1ffffff);
	{ u64 x103 = (x101 + x67);
	{ u64 x104 = (x103 >> 0x1a);
	{ u32 x105 = ((u32)x103 & 0x3ffffff);
	{ u64 x106 = (x104 + x64);
	{ u64 x107 = (x106 >> 0x19);
	{ u32 x108 = ((u32)x106 & 0x1ffffff);
	{ u64 x109 = (x107 + x61);
	{ u64 x110 = (x109 >> 0x1a);
	{ u32 x111 = ((u32)x109 & 0x3ffffff);
	{ u64 x112 = (x110 + x49);
	{ u64 x113 = (x112 >> 0x19);
	{ u32 x114 = ((u32)x112 & 0x1ffffff);
	{ u64 x115 = (x87 + (0x13 * x113));
	{ u32 x116 = (u32) (x115 >> 0x1a);
	{ u32 x117 = ((u32)x115 & 0x3ffffff);
	{ u32 x118 = (x116 + x90);
	{ u32 x119 = (x118 >> 0x19);
	{ u32 x120 = (x118 & 0x1ffffff);
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
#endif

static __always_inline void fe_frombytes(fe *h, const u8 *s)
{
	fe_frombytes_impl(h->v, s);
}

/* h = f */
static __always_inline void fe_copy(fe *h, const fe *f)
{
	memmove(h, f, sizeof(fe));
}

static __always_inline void fe_copy_lt(fe_loose *h, const fe *f)
{
	memmove(h, f, sizeof(fe));
}

/* h = 0 */
static __always_inline void fe_0(fe *h)
{
	memset(h, 0, sizeof(fe));
}

/* h = 1 */
static __always_inline void fe_1(fe *h)
{
	memset(h, 0, sizeof(fe));
	h->v[0] = 1;
}

/* h = f + g
 * Can overlap h with f or g.
 */
static __always_inline void fe_add(fe_loose *h, const fe *f, const fe *g)
{
	fe_add_impl(h->v, f->v, g->v);
}

/* h = f - g
 * Can overlap h with f or g.
 */
static __always_inline void fe_sub(fe_loose *h, const fe *f, const fe *g)
{
	fe_sub_impl(h->v, f->v, g->v);
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

static __always_inline void fe_mul121666(fe *h, const fe_loose *f)
{
	fe_mul_121666_impl(h->v, f->v);
}

static void curve25519_generic(u8 out[CURVE25519_POINT_SIZE], const u8 scalar[CURVE25519_POINT_SIZE], const u8 point[CURVE25519_POINT_SIZE])
{
	fe x1, x2, z2, x3, z3, tmp0, tmp1;
	fe_loose x2l, z2l, x3l, tmp0l, tmp1l;
	unsigned swap = 0;
	int pos;
	u8 e[32];

	memcpy(e, scalar, 32);
	normalize_secret(e);

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

	memzero_explicit(&x1, sizeof(x1));
	memzero_explicit(&x2, sizeof(x2));
	memzero_explicit(&z2, sizeof(z2));
	memzero_explicit(&x3, sizeof(x3));
	memzero_explicit(&z3, sizeof(z3));
	memzero_explicit(&tmp0, sizeof(tmp0));
	memzero_explicit(&tmp1, sizeof(tmp1));
	memzero_explicit(&x2l, sizeof(x2l));
	memzero_explicit(&z2l, sizeof(z2l));
	memzero_explicit(&x3l, sizeof(x3l));
	memzero_explicit(&tmp0l, sizeof(tmp0l));
	memzero_explicit(&tmp1l, sizeof(tmp1l));
	memzero_explicit(&e, sizeof(e));
}
