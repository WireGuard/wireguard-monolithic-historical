/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_CHACHA20POLY1305_H
#define _WG_CHACHA20POLY1305_H

#include <linux/types.h>

struct scatterlist;

enum chacha20poly1305_lengths {
	XCHACHA20POLY1305_NONCELEN = 24,
	CHACHA20POLY1305_KEYLEN = 32,
	CHACHA20POLY1305_AUTHTAGLEN = 16
};

void chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN]);

bool __must_check chacha20poly1305_encrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd);

bool __must_check chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
					   const u8 *ad, const size_t ad_len,
					   const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN]);

bool __must_check chacha20poly1305_decrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd);

void xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN]);

bool __must_check xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
					    const u8 *ad, const size_t ad_len,
					    const u8 nonce[XCHACHA20POLY1305_NONCELEN],
					    const u8 key[CHACHA20POLY1305_KEYLEN]);

#ifdef DEBUG
bool chacha20poly1305_selftest(void);
#endif

#endif /* _WG_CHACHA20POLY1305_H */
