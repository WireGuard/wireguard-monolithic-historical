/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <linux/types.h>

struct scatterlist;

enum chacha20poly1305_lengths {
	CHACHA20POLY1305_KEYLEN = 32,
	CHACHA20POLY1305_AUTHTAGLEN = 16
};

void chacha20poly1305_init(void);

bool chacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, const size_t src_len,
			      const uint8_t *ad, const size_t ad_len,
			      const uint64_t nonce, const uint8_t key[CHACHA20POLY1305_KEYLEN]);

bool chacha20poly1305_encrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const uint8_t *ad, const size_t ad_len,
				 const uint64_t nonce, const uint8_t key[CHACHA20POLY1305_KEYLEN],
				 bool have_simd);

bool chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, const size_t src_len,
			      const uint8_t *ad, const size_t ad_len,
			      const uint64_t nonce, const uint8_t key[CHACHA20POLY1305_KEYLEN]);

bool chacha20poly1305_decrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const uint8_t *ad, const size_t ad_len,
				 const uint64_t nonce, const uint8_t key[CHACHA20POLY1305_KEYLEN]);

#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
#include <asm/fpu/api.h>
#include <asm/simd.h>
#else
#include <asm/i387.h>
#endif
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
