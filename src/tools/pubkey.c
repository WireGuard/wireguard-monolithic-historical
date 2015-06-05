/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <errno.h>
#include <resolv.h>
#include <stdio.h>

#include "curve25519.h"
#include "base64.h"

int pubkey_main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[])
{
	unsigned char private_key[CURVE25519_POINT_SIZE + 1] = { 0 }, public_key[CURVE25519_POINT_SIZE] = { 0 };
	char private_key_base64[b64_len(CURVE25519_POINT_SIZE)] = { 0 }, public_key_base64[b64_len(CURVE25519_POINT_SIZE)] = { 0 };

	if (fread(private_key_base64, 1, sizeof(private_key_base64) - 1, stdin) != sizeof(private_key_base64) - 1) {
		errno = EINVAL;
		perror("fread(private key)");
		return 1;
	}
	if (b64_pton(private_key_base64, private_key, sizeof(private_key)) < 0) {
		errno = EINVAL;
		perror("b64");
		return 1;
	}
	curve25519_generate_public(public_key, private_key);
	if (b64_ntop(public_key, sizeof(public_key), public_key_base64, sizeof(public_key_base64)) < 0) {
		errno = EINVAL;
		perror("b64");
		return 1;
	}
	puts(public_key_base64);
	return 0;
}
