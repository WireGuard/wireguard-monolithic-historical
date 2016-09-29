/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "siphash24.h"

#include <linux/kernel.h>

#define ROTL(x,b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define U8TO64(p) le64_to_cpu(*(__le64 *)(p))

#define SIPROUND \
	do { \
	v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32); \
	v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32); \
	} while(0)

__attribute__((optimize("unroll-loops")))
uint64_t siphash24(const uint8_t *data, size_t len, const uint8_t key[static SIPHASH24_KEY_LEN])
{
	uint64_t v0 = 0x736f6d6570736575ULL;
	uint64_t v1 = 0x646f72616e646f6dULL;
	uint64_t v2 = 0x6c7967656e657261ULL;
	uint64_t v3 = 0x7465646279746573ULL;
	uint64_t b;
	uint64_t k0 = U8TO64(key);
	uint64_t k1 = U8TO64(key + sizeof(uint64_t));
	uint64_t m;
	const uint8_t *end = data + len - (len % sizeof(uint64_t));
	const uint8_t left = len & (sizeof(uint64_t) - 1);
	b = ((uint64_t)len) << 56;
	v3 ^= k1;
	v2 ^= k0;
	v1 ^= k1;
	v0 ^= k0;
	for (; data != end; data += sizeof(uint64_t)) {
		m = U8TO64(data);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}
	switch (left) {
		case 7: b |= ((uint64_t)data[6]) << 48;
		case 6: b |= ((uint64_t)data[5]) << 40;
		case 5: b |= ((uint64_t)data[4]) << 32;
		case 4: b |= ((uint64_t)data[3]) << 24;
		case 3: b |= ((uint64_t)data[2]) << 16;
		case 2: b |= ((uint64_t)data[1]) <<  8;
		case 1: b |= ((uint64_t)data[0]); break;
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
	return (__force uint64_t)cpu_to_le64(b);
}

#include "../selftest/siphash24.h"
