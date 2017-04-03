/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <linux/types.h>

struct scatterlist;

enum chacha20poly1305_lengths {
	XCHACHA20POLY1305_NONCELEN = 24,
	CHACHA20POLY1305_KEYLEN = 32,
	CHACHA20POLY1305_AUTHTAGLEN = 16
};

void chacha20poly1305_fpu_init(void);

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
				 const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN]);

void xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN]);

bool __must_check xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN]);

#ifdef CONFIG_X86_64
#include <linux/version.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>
#endif

static inline bool chacha20poly1305_init_simd(void)
{
	bool have_simd = false;
#ifdef CONFIG_X86_64
	have_simd = irq_fpu_usable();
	if (have_simd)
		kernel_fpu_begin();
#endif
	return have_simd;
}

static inline void chacha20poly1305_deinit_simd(bool was_on)
{
#ifdef CONFIG_X86_64
	if (was_on)
		kernel_fpu_end();
#endif
}

#ifdef DEBUG
bool chacha20poly1305_selftest(void);
#endif

#endif
