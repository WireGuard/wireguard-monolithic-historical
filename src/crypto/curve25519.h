/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef CURVE25519_H
#define CURVE25519_H

#include <linux/types.h>

enum curve25519_lengths {
	CURVE25519_POINT_SIZE = 32
};

void curve25519(u8 mypublic[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE], const u8 basepoint[CURVE25519_POINT_SIZE]);
void curve25519_generate_secret(u8 secret[CURVE25519_POINT_SIZE]);
void curve25519_generate_public(u8 pub[CURVE25519_POINT_SIZE], const u8 secret[CURVE25519_POINT_SIZE]);

#ifdef DEBUG
bool curve25519_selftest(void);
#endif

#endif
