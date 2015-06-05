/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <linux/types.h>

enum blake2s_lengths {
	BLAKE2S_BLOCKBYTES = 64,
	BLAKE2S_OUTBYTES = 32,
	BLAKE2S_KEYBYTES = 32
};

struct blake2s_state {
	uint32_t h[8];
	uint32_t t[2];
	uint32_t f[2];
	uint8_t buf[2 * BLAKE2S_BLOCKBYTES];
	size_t buflen;
	uint8_t last_node;
};

void blake2s(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t outlen, const uint64_t inlen, const uint8_t keylen);

void blake2s_init(struct blake2s_state *state, const uint8_t outlen);
void blake2s_init_key(struct blake2s_state *state, const uint8_t outlen, const void *key, const uint8_t keylen);
void blake2s_update(struct blake2s_state *state, const uint8_t *in, uint64_t inlen);
void blake2s_final(struct blake2s_state *state, uint8_t *out, uint8_t outlen);

void blake2s_hmac(uint8_t *out, const uint8_t *in, const uint8_t *key, const uint8_t outlen, const uint64_t inlen, const uint64_t keylen);

#ifdef DEBUG
void blake2s_selftest(void);
#endif

#endif
