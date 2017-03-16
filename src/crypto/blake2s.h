/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <linux/types.h>

enum blake2s_lengths {
	BLAKE2S_BLOCKBYTES = 64,
	BLAKE2S_OUTBYTES = 32,
	BLAKE2S_KEYBYTES = 32
};

struct blake2s_state {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[2 * BLAKE2S_BLOCKBYTES];
	size_t buflen;
	u8 last_node;
};

void blake2s(u8 *out, const u8 *in, const u8 *key, const u8 outlen, const u64 inlen, const u8 keylen);

void blake2s_init(struct blake2s_state *state, const u8 outlen);
void blake2s_init_key(struct blake2s_state *state, const u8 outlen, const void *key, const u8 keylen);
void blake2s_update(struct blake2s_state *state, const u8 *in, u64 inlen);
void blake2s_final(struct blake2s_state *state, u8 *out, u8 outlen);

void blake2s_hmac(u8 *out, const u8 *in, const u8 *key, const u8 outlen, const u64 inlen, const u64 keylen);

void blake2s_fpu_init(void);

#ifdef DEBUG
bool blake2s_selftest(void);
#endif

#endif
