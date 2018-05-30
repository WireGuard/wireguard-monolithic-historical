/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "chacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"

#include <linux/kernel.h>
#include <crypto/scatterwalk.h>

static const u8 pad0[16] = { 0 };

static struct crypto_alg chacha20_alg = {
	.cra_blocksize = 1,
	.cra_alignmask = sizeof(u32) - 1
};
static struct crypto_blkcipher chacha20_cipher = {
	.base = {
		.__crt_alg = &chacha20_alg
	}
};
static struct blkcipher_desc chacha20_desc = {
	.tfm = &chacha20_cipher
};

static inline void __chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	union {
		u8 block0[POLY1305_KEY_SIZE];
		__le64 lens[2];
	} b = {{ 0 }};

	chacha20_init(&chacha20_state, key, nonce);
	chacha20(&chacha20_state, b.block0, b.block0, sizeof(b.block0), have_simd);
	poly1305_init(&poly1305_state, b.block0, have_simd);

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	chacha20(&chacha20_state, dst, src, src_len, have_simd);

	poly1305_update(&poly1305_state, dst, src_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - src_len) & 0xf, have_simd);

	b.lens[0] = cpu_to_le64(ad_len);
	b.lens[1] = cpu_to_le64(src_len);
	poly1305_update(&poly1305_state, (u8 *)b.lens, sizeof(b.lens), have_simd);

	poly1305_finish(&poly1305_state, dst + src_len, have_simd);

	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	memzero_explicit(&b, sizeof(b));
}

void chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd;

	have_simd = chacha20poly1305_init_simd();
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, nonce, key, have_simd);
	chacha20poly1305_deinit_simd(have_simd);
}

bool chacha20poly1305_encrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const u8 *ad, const size_t ad_len,
				 const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
				 bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	int ret = 0;
	struct blkcipher_walk walk;
	union {
		u8 block0[POLY1305_KEY_SIZE];
		u8 mac[POLY1305_MAC_SIZE];
		__le64 lens[2];
	} b = {{ 0 }};

	chacha20_init(&chacha20_state, key, nonce);
	chacha20(&chacha20_state, b.block0, b.block0, sizeof(b.block0), have_simd);
	poly1305_init(&poly1305_state, b.block0, have_simd);

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	if (likely(src_len)) {
		blkcipher_walk_init(&walk, dst, src, src_len);
		ret = blkcipher_walk_virt_block(&chacha20_desc, &walk, CHACHA20_BLOCK_SIZE);
		while (walk.nbytes >= CHACHA20_BLOCK_SIZE) {
			size_t chunk_len = rounddown(walk.nbytes, CHACHA20_BLOCK_SIZE);

			chacha20(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, chunk_len, have_simd);
			poly1305_update(&poly1305_state, walk.dst.virt.addr, chunk_len, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, walk.nbytes % CHACHA20_BLOCK_SIZE);
		}
		if (walk.nbytes) {
			chacha20(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, walk.nbytes, have_simd);
			poly1305_update(&poly1305_state, walk.dst.virt.addr, walk.nbytes, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, 0);
		}
	}
	if (unlikely(ret))
		goto err;

	poly1305_update(&poly1305_state, pad0, (0x10 - src_len) & 0xf, have_simd);

	b.lens[0] = cpu_to_le64(ad_len);
	b.lens[1] = cpu_to_le64(src_len);
	poly1305_update(&poly1305_state, (u8 *)b.lens, sizeof(b.lens), have_simd);

	poly1305_finish(&poly1305_state, b.mac, have_simd);
	scatterwalk_map_and_copy(b.mac, dst, src_len, sizeof(b.mac), 1);
err:
	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	memzero_explicit(&b, sizeof(b));
	return !ret;
}

static inline bool __chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
					      const u8 *ad, const size_t ad_len,
					      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
					      bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	int ret;
	size_t dst_len;
	union {
		u8 block0[POLY1305_KEY_SIZE];
		u8 mac[POLY1305_MAC_SIZE];
		__le64 lens[2];
	} b = {{ 0 }};

	if (unlikely(src_len < POLY1305_MAC_SIZE))
		return false;

	chacha20_init(&chacha20_state, key, nonce);
	chacha20(&chacha20_state, b.block0, b.block0, sizeof(b.block0), have_simd);
	poly1305_init(&poly1305_state, b.block0, have_simd);

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	dst_len = src_len - POLY1305_MAC_SIZE;
	poly1305_update(&poly1305_state, src, dst_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - dst_len) & 0xf, have_simd);

	b.lens[0] = cpu_to_le64(ad_len);
	b.lens[1] = cpu_to_le64(dst_len);
	poly1305_update(&poly1305_state, (u8 *)b.lens, sizeof(b.lens), have_simd);

	poly1305_finish(&poly1305_state, b.mac, have_simd);

	ret = crypto_memneq(b.mac, src + dst_len, POLY1305_MAC_SIZE);
	if (likely(!ret))
		chacha20(&chacha20_state, dst, src, dst_len, have_simd);

	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	memzero_explicit(&b, sizeof(b));

	return !ret;
}

bool chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd, ret;

	have_simd = chacha20poly1305_init_simd();
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, nonce, key, have_simd);
	chacha20poly1305_deinit_simd(have_simd);
	return ret;
}

bool chacha20poly1305_decrypt_sg(struct scatterlist *dst, struct scatterlist *src, const size_t src_len,
				 const u8 *ad, const size_t ad_len,
				 const u64 nonce, const u8 key[CHACHA20POLY1305_KEYLEN],
				 bool have_simd)
{
	struct poly1305_ctx poly1305_state;
	struct chacha20_ctx chacha20_state;
	struct blkcipher_walk walk;
	int ret = 0;
	size_t dst_len;
	union {
		u8 block0[POLY1305_KEY_SIZE];
		struct {
			u8 read_mac[POLY1305_MAC_SIZE];
			u8 computed_mac[POLY1305_MAC_SIZE];
		};
		__le64 lens[2];
	} b = {{ 0 }};

	if (unlikely(src_len < POLY1305_MAC_SIZE))
		return false;

	chacha20_init(&chacha20_state, key, nonce);
	chacha20(&chacha20_state, b.block0, b.block0, sizeof(b.block0), have_simd);
	poly1305_init(&poly1305_state, b.block0, have_simd);

	poly1305_update(&poly1305_state, ad, ad_len, have_simd);
	poly1305_update(&poly1305_state, pad0, (0x10 - ad_len) & 0xf, have_simd);

	dst_len = src_len - POLY1305_MAC_SIZE;
	if (likely(dst_len)) {
		blkcipher_walk_init(&walk, dst, src, dst_len);
		ret = blkcipher_walk_virt_block(&chacha20_desc, &walk, CHACHA20_BLOCK_SIZE);
		while (walk.nbytes >= CHACHA20_BLOCK_SIZE) {
			size_t chunk_len = rounddown(walk.nbytes, CHACHA20_BLOCK_SIZE);

			poly1305_update(&poly1305_state, walk.src.virt.addr, chunk_len, have_simd);
			chacha20(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, chunk_len, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, walk.nbytes % CHACHA20_BLOCK_SIZE);
		}
		if (walk.nbytes) {
			poly1305_update(&poly1305_state, walk.src.virt.addr, walk.nbytes, have_simd);
			chacha20(&chacha20_state, walk.dst.virt.addr, walk.src.virt.addr, walk.nbytes, have_simd);
			ret = blkcipher_walk_done(&chacha20_desc, &walk, 0);
		}
	}
	if (unlikely(ret))
		goto err;

	poly1305_update(&poly1305_state, pad0, (0x10 - dst_len) & 0xf, have_simd);

	b.lens[0] = cpu_to_le64(ad_len);
	b.lens[1] = cpu_to_le64(dst_len);
	poly1305_update(&poly1305_state, (u8 *)b.lens, sizeof(b.lens), have_simd);

	poly1305_finish(&poly1305_state, b.computed_mac, have_simd);

	scatterwalk_map_and_copy(b.read_mac, src, dst_len, POLY1305_MAC_SIZE, 0);
	ret = crypto_memneq(b.read_mac, b.computed_mac, POLY1305_MAC_SIZE);
err:
	memzero_explicit(&chacha20_state, sizeof(chacha20_state));
	memzero_explicit(&b, sizeof(b));
	return !ret;
}


void xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool have_simd = chacha20poly1305_init_simd();
	u8 derived_key[CHACHA20POLY1305_KEYLEN] __aligned(16);

	hchacha20(derived_key, nonce, key, have_simd);
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, le64_to_cpup((__le64 *)(nonce + 16)), derived_key, have_simd);
	memzero_explicit(derived_key, CHACHA20POLY1305_KEYLEN);
	chacha20poly1305_deinit_simd(have_simd);
}

bool xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[XCHACHA20POLY1305_NONCELEN],
			       const u8 key[CHACHA20POLY1305_KEYLEN])
{
	bool ret, have_simd = chacha20poly1305_init_simd();
	u8 derived_key[CHACHA20POLY1305_KEYLEN] __aligned(16);

	hchacha20(derived_key, nonce, key, have_simd);
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, le64_to_cpup((__le64 *)(nonce + 16)), derived_key, have_simd);
	memzero_explicit(derived_key, CHACHA20POLY1305_KEYLEN);
	chacha20poly1305_deinit_simd(have_simd);
	return ret;
}

#include "../selftest/chacha20poly1305.h"
