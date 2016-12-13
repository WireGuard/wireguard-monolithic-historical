/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4.
 */

#include "siphash.h"
#include <asm/unaligned.h>

#if defined(CONFIG_DCACHE_WORD_ACCESS) && BITS_PER_LONG == 64
#include <linux/dcache.h>
#include <asm/word-at-a-time.h>
#endif

#define SIPROUND \
	do { \
	v0 += v1; v1 = rol64(v1, 13); v1 ^= v0; v0 = rol64(v0, 32); \
	v2 += v3; v3 = rol64(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = rol64(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = rol64(v1, 17); v1 ^= v2; v2 = rol64(v2, 32); \
	} while(0)

#define PREAMBLE(len) \
	u64 v0 = 0x736f6d6570736575ULL; \
	u64 v1 = 0x646f72616e646f6dULL; \
	u64 v2 = 0x6c7967656e657261ULL; \
	u64 v3 = 0x7465646279746573ULL; \
	u64 b = ((u64)len) << 56; \
	v3 ^= key[1]; \
	v2 ^= key[0]; \
	v1 ^= key[1]; \
	v0 ^= key[0];

#define POSTAMBLE \
	v3 ^= b; \
	SIPROUND; \
	SIPROUND; \
	v0 ^= b; \
	v2 ^= 0xff; \
	SIPROUND; \
	SIPROUND; \
	SIPROUND; \
	SIPROUND; \
	return (v0 ^ v1) ^ (v2 ^ v3);

u64 __siphash_aligned(const void *data, size_t len, const siphash_key_t key)
{
	const u8 *end = data + len - (len % sizeof(u64));
	const u8 left = len & (sizeof(u64) - 1);
	u64 m;
	PREAMBLE(len)
	for (; data != end; data += sizeof(u64)) {
		m = le64_to_cpup(data);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}
#if defined(CONFIG_DCACHE_WORD_ACCESS) && BITS_PER_LONG == 64
	if (left)
		b |= le64_to_cpu((__force __le64)(load_unaligned_zeropad(data) &
						  bytemask_from_count(left)));
#else
	switch (left) {
	case 7: b |= ((u64)end[6]) << 48;
	case 6: b |= ((u64)end[5]) << 40;
	case 5: b |= ((u64)end[4]) << 32;
	case 4: b |= le32_to_cpup(data); break;
	case 3: b |= ((u64)end[2]) << 16;
	case 2: b |= le16_to_cpup(data); break;
	case 1: b |= end[0];
	}
#endif
	POSTAMBLE
}

#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
u64 __siphash_unaligned(const void *data, size_t len, const siphash_key_t key)
{
	const u8 *end = data + len - (len % sizeof(u64));
	const u8 left = len & (sizeof(u64) - 1);
	u64 m;
	PREAMBLE(len)
	for (; data != end; data += sizeof(u64)) {
		m = get_unaligned_le64(data);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}
#if defined(CONFIG_DCACHE_WORD_ACCESS) && BITS_PER_LONG == 64
	if (left)
		b |= le64_to_cpu((__force __le64)(load_unaligned_zeropad(data) &
						  bytemask_from_count(left)));
#else
	switch (left) {
	case 7: b |= ((u64)end[6]) << 48;
	case 6: b |= ((u64)end[5]) << 40;
	case 5: b |= ((u64)end[4]) << 32;
	case 4: b |= get_unaligned_le32(end); break;
	case 3: b |= ((u64)end[2]) << 16;
	case 2: b |= get_unaligned_le16(end); break;
	case 1: b |= end[0];
	}
#endif
	POSTAMBLE
}
#endif

/**
 * siphash_1u64 - compute 64-bit siphash PRF value of a u64
 * @first: first u64
 * @key: the siphash key
 */
u64 siphash_1u64(const u64 first, const siphash_key_t key)
{
	PREAMBLE(8)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	POSTAMBLE
}

/**
 * siphash_2u64 - compute 64-bit siphash PRF value of 2 u64
 * @first: first u64
 * @second: second u64
 * @key: the siphash key
 */
u64 siphash_2u64(const u64 first, const u64 second, const siphash_key_t key)
{
	PREAMBLE(16)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	v3 ^= second;
	SIPROUND;
	SIPROUND;
	v0 ^= second;
	POSTAMBLE
}

/**
 * siphash_3u64 - compute 64-bit siphash PRF value of 3 u64
 * @first: first u64
 * @second: second u64
 * @third: third u64
 * @key: the siphash key
 */
u64 siphash_3u64(const u64 first, const u64 second, const u64 third,
		 const siphash_key_t key)
{
	PREAMBLE(24)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	v3 ^= second;
	SIPROUND;
	SIPROUND;
	v0 ^= second;
	v3 ^= third;
	SIPROUND;
	SIPROUND;
	v0 ^= third;
	POSTAMBLE
}

/**
 * siphash_4u64 - compute 64-bit siphash PRF value of 4 u64
 * @first: first u64
 * @second: second u64
 * @third: third u64
 * @forth: forth u64
 * @key: the siphash key
 */
u64 siphash_4u64(const u64 first, const u64 second, const u64 third,
		 const u64 forth, const siphash_key_t key)
{
	PREAMBLE(32)
	v3 ^= first;
	SIPROUND;
	SIPROUND;
	v0 ^= first;
	v3 ^= second;
	SIPROUND;
	SIPROUND;
	v0 ^= second;
	v3 ^= third;
	SIPROUND;
	SIPROUND;
	v0 ^= third;
	v3 ^= forth;
	SIPROUND;
	SIPROUND;
	v0 ^= forth;
	POSTAMBLE
}

#include "../selftest/siphash.h"
