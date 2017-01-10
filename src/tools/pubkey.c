/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <errno.h>
#include <resolv.h>
#include <stdio.h>
#include <ctype.h>

#include "curve25519.h"
#include "base64.h"
#include "subcommands.h"

int pubkey_main(int argc, char *argv[])
{
	unsigned char private_key[CURVE25519_POINT_SIZE + 1] = { 0 }, public_key[CURVE25519_POINT_SIZE] = { 0 };
	char private_key_base64[b64_len(CURVE25519_POINT_SIZE)] = { 0 }, public_key_base64[b64_len(CURVE25519_POINT_SIZE)] = { 0 };
	int trailing_char;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (fread(private_key_base64, 1, sizeof(private_key_base64) - 1, stdin) != sizeof(private_key_base64) - 1) {
		errno = EINVAL;
		fprintf(stderr, "%s: Key is not the correct length or format\n", PROG_NAME);
		return 1;
	}

	for (;;) {
		trailing_char = getc(stdin);
		if (!trailing_char || isspace(trailing_char) || isblank(trailing_char))
			continue;
		if (trailing_char == EOF)
			break;
		fprintf(stderr, "%s: Trailing characters found after key\n", PROG_NAME);
		return 1;
	}

	if (b64_pton(private_key_base64, private_key, sizeof(private_key)) != sizeof(private_key) - 1) {
		fprintf(stderr, "%s: Key is not the correct length or format\n", PROG_NAME);
		return 1;
	}
	curve25519_generate_public(public_key, private_key);
	if (b64_ntop(public_key, sizeof(public_key), public_key_base64, sizeof(public_key_base64)) != sizeof(public_key_base64) - 1) {
		fprintf(stderr, "%s: Could not convert key to base64\n", PROG_NAME);
		return 1;
	}
	puts(public_key_base64);
	return 0;
}
