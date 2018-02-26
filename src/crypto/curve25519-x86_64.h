/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Based on algorithms from Tung Chou <blueprint@crypto.tw>
 */

#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>

static bool curve25519_use_avx __ro_after_init;
void __init curve25519_fpu_init(void)
{
#ifndef CONFIG_UML
	curve25519_use_avx = boot_cpu_has(X86_FEATURE_AVX) && cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL);
#endif
}

typedef u64 fex[10];
typedef u64 fe51[5];
asmlinkage void curve25519_sandy2x_ladder(fex *, const u8 *);
asmlinkage void curve25519_sandy2x_ladder_base(fex *, const u8 *);
asmlinkage void curve25519_sandy2x_fe51_pack(u8 *, const fe51 *);
asmlinkage void curve25519_sandy2x_fe51_mul(fe51 *, const fe51 *, const fe51 *);
asmlinkage void curve25519_sandy2x_fe51_nsquare(fe51 *, const fe51 *, int);

static inline u32 le24_to_cpupv(const u8 *in)
{
	return le16_to_cpup((__le16 *)in) | ((u32)in[2]) << 16;
}

static inline void fex_frombytes(fex h, const u8 *s)
{
	u64 h0 = le32_to_cpup((__le32 *)s);
	u64 h1 = le24_to_cpupv(s + 4) << 6;
	u64 h2 = le24_to_cpupv(s + 7) << 5;
	u64 h3 = le24_to_cpupv(s + 10) << 3;
	u64 h4 = le24_to_cpupv(s + 13) << 2;
	u64 h5 = le32_to_cpup((__le32 *)(s + 16));
	u64 h6 = le24_to_cpupv(s + 20) << 7;
	u64 h7 = le24_to_cpupv(s + 23) << 5;
	u64 h8 = le24_to_cpupv(s + 26) << 4;
	u64 h9 = (le24_to_cpupv(s + 29) & 8388607) << 2;
	u64 carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9;

	carry9 = h9 >> 25; h0 += carry9 * 19; h9 &= 0x1FFFFFF;
	carry1 = h1 >> 25; h2 += carry1; h1 &= 0x1FFFFFF;
	carry3 = h3 >> 25; h4 += carry3; h3 &= 0x1FFFFFF;
	carry5 = h5 >> 25; h6 += carry5; h5 &= 0x1FFFFFF;
	carry7 = h7 >> 25; h8 += carry7; h7 &= 0x1FFFFFF;

	carry0 = h0 >> 26; h1 += carry0; h0 &= 0x3FFFFFF;
	carry2 = h2 >> 26; h3 += carry2; h2 &= 0x3FFFFFF;
	carry4 = h4 >> 26; h5 += carry4; h4 &= 0x3FFFFFF;
	carry6 = h6 >> 26; h7 += carry6; h6 &= 0x3FFFFFF;
	carry8 = h8 >> 26; h9 += carry8; h8 &= 0x3FFFFFF;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}

static inline void fe51_invert(fe51 *r, const fe51 *x)
{
	fe51 z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t;

	/* 2 */ curve25519_sandy2x_fe51_nsquare(&z2, x, 1);
	/* 4 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2, 1);
	/* 8 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 1);
	/* 9 */ curve25519_sandy2x_fe51_mul(&z9, (const fe51 *)&t, x);
	/* 11 */ curve25519_sandy2x_fe51_mul(&z11, (const fe51 *)&z9, (const fe51 *)&z2);
	/* 22 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z11, 1);
	/* 2^5 - 2^0 = 31 */ curve25519_sandy2x_fe51_mul(&z2_5_0, (const fe51 *)&t, (const fe51 *)&z9);

	/* 2^10 - 2^5 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_5_0, 5);
	/* 2^10 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_10_0, (const fe51 *)&t, (const fe51 *)&z2_5_0);

	/* 2^20 - 2^10 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_10_0, 10);
	/* 2^20 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_20_0, (const fe51 *)&t, (const fe51 *)&z2_10_0);

	/* 2^40 - 2^20 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_20_0, 20);
	/* 2^40 - 2^0 */ curve25519_sandy2x_fe51_mul(&t, (const fe51 *)&t, (const fe51 *)&z2_20_0);

	/* 2^50 - 2^10 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 10);
	/* 2^50 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_50_0, (const fe51 *)&t, (const fe51 *)&z2_10_0);

	/* 2^100 - 2^50 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_50_0, 50);
	/* 2^100 - 2^0 */ curve25519_sandy2x_fe51_mul(&z2_100_0, (const fe51 *)&t, (const fe51 *)&z2_50_0);

	/* 2^200 - 2^100 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&z2_100_0, 100);
	/* 2^200 - 2^0 */ curve25519_sandy2x_fe51_mul(&t, (const fe51 *)&t, (const fe51 *)&z2_100_0);

	/* 2^250 - 2^50 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 50);
	/* 2^250 - 2^0 */ curve25519_sandy2x_fe51_mul(&t, (const fe51 *)&t, (const fe51 *)&z2_50_0);

	/* 2^255 - 2^5 */ curve25519_sandy2x_fe51_nsquare(&t, (const fe51 *)&t, 5);
	/* 2^255 - 21 */ curve25519_sandy2x_fe51_mul(r, (const fe51 *)t, (const fe51 *)&z11);
}

static void curve25519_sandy2x(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE])
{
	u8 e[32];
	fex var[3];
	fe51 x_51, z_51;

	memcpy(e, secret, 32);
	normalize_secret(e);
#define x1 var[0]
#define x2 var[1]
#define z2 var[2]
	fex_frombytes(x1, basepoint);
	curve25519_sandy2x_ladder(var, e);
	z_51[0] = (z2[1] << 26) + z2[0];
	z_51[1] = (z2[3] << 26) + z2[2];
	z_51[2] = (z2[5] << 26) + z2[4];
	z_51[3] = (z2[7] << 26) + z2[6];
	z_51[4] = (z2[9] << 26) + z2[8];
	x_51[0] = (x2[1] << 26) + x2[0];
	x_51[1] = (x2[3] << 26) + x2[2];
	x_51[2] = (x2[5] << 26) + x2[4];
	x_51[3] = (x2[7] << 26) + x2[6];
	x_51[4] = (x2[9] << 26) + x2[8];
#undef x1
#undef x2
#undef z2
	fe51_invert(&z_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_mul(&x_51, (const fe51 *)&x_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_pack(mypublic, (const fe51 *)&x_51);

	memzero_explicit(e, sizeof(e));
	memzero_explicit(var, sizeof(var));
	memzero_explicit(x_51, sizeof(x_51));
	memzero_explicit(z_51, sizeof(z_51));
}

static void curve25519_sandy2x_base(u8 pub[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE])
{
	u8 e[32];
	fex var[3];
	fe51 x_51, z_51;

	memcpy(e, secret, 32);
	normalize_secret(e);
	curve25519_sandy2x_ladder_base(var, e);
#define x2 var[0]
#define z2 var[1]
	z_51[0] = (z2[1] << 26) + z2[0];
	z_51[1] = (z2[3] << 26) + z2[2];
	z_51[2] = (z2[5] << 26) + z2[4];
	z_51[3] = (z2[7] << 26) + z2[6];
	z_51[4] = (z2[9] << 26) + z2[8];
	x_51[0] = (x2[1] << 26) + x2[0];
	x_51[1] = (x2[3] << 26) + x2[2];
	x_51[2] = (x2[5] << 26) + x2[4];
	x_51[3] = (x2[7] << 26) + x2[6];
	x_51[4] = (x2[9] << 26) + x2[8];
#undef x2
#undef z2
	fe51_invert(&z_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_mul(&x_51, (const fe51 *)&x_51, (const fe51 *)&z_51);
	curve25519_sandy2x_fe51_pack(pub, (const fe51 *)&x_51);

	memzero_explicit(e, sizeof(e));
	memzero_explicit(var, sizeof(var));
	memzero_explicit(x_51, sizeof(x_51));
	memzero_explicit(z_51, sizeof(z_51));
}
