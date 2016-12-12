/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "siphash24.h"

#include <linux/kernel.h>

static inline u64 le64_to_cpuvp(const void *p)
{
	return le64_to_cpup(p);
}

#define SIPROUND \
	do { \
	v0 += v1; v1 = rol64(v1, 13); v1 ^= v0; v0 = rol64(v0, 32); \
	v2 += v3; v3 = rol64(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = rol64(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = rol64(v1, 17); v1 ^= v2; v2 = rol64(v2, 32); \
	} while(0)

u64 siphash24(const u8 *data, size_t len, const u8 key[SIPHASH24_KEY_LEN])
{
	u64 v0 = 0x736f6d6570736575ULL;
	u64 v1 = 0x646f72616e646f6dULL;
	u64 v2 = 0x6c7967656e657261ULL;
	u64 v3 = 0x7465646279746573ULL;
	u64 b = ((u64)len) << 56;
	u64 k0 = le64_to_cpuvp(key);
	u64 k1 = le64_to_cpuvp(key + sizeof(u64));
	u64 m;
	const u8 *end = data + len - (len % sizeof(u64));
	const u8 left = len & (sizeof(u64) - 1);
	v3 ^= k1;
	v2 ^= k0;
	v1 ^= k1;
	v0 ^= k0;
	for (; data != end; data += sizeof(u64)) {
		m = le64_to_cpuvp(data);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}
	switch (left) {
		case 7: b |= ((u64)data[6]) << 48;
		case 6: b |= ((u64)data[5]) << 40;
		case 5: b |= ((u64)data[4]) << 32;
		case 4: b |= ((u64)data[3]) << 24;
		case 3: b |= ((u64)data[2]) << 16;
		case 2: b |= ((u64)data[1]) <<  8;
		case 1: b |= ((u64)data[0]); break;
		case 0: break;
	}
	v3 ^= b;
	SIPROUND;
	SIPROUND;
	v0 ^= b;
	v2 ^= 0xff;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;
	b = (v0 ^ v1) ^ (v2 ^ v3);
	return (__force u64)cpu_to_le64(b);
}

#include "../selftest/siphash24.h"
