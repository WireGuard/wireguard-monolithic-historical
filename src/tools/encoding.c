/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is a specialized constant-time base64/hex implementation that resists side-channel attacks.
 */

#include <string.h>
#include "encoding.h"

static inline void encode_base64(char dest[4], const uint8_t src[3])
{
	const uint8_t input[] = { (src[0] >> 2) & 63, ((src[0] << 4) | (src[1] >> 4)) & 63, ((src[1] << 2) | (src[2] >> 6)) & 63, src[2] & 63 };

	for (unsigned int i = 0; i < 4; ++i)
		dest[i] = input[i] + 'A'
			  + (((25 - input[i]) >> 8) & 6)
			  - (((51 - input[i]) >> 8) & 75)
			  - (((61 - input[i]) >> 8) & 15)
			  + (((62 - input[i]) >> 8) & 3);

}

void key_to_base64(char base64[static WG_KEY_LEN_BASE64], const uint8_t key[static WG_KEY_LEN])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN / 3; ++i)
		encode_base64(&base64[i * 4], &key[i * 3]);
	encode_base64(&base64[i * 4], (const uint8_t[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
	base64[WG_KEY_LEN_BASE64 - 2] = '=';
	base64[WG_KEY_LEN_BASE64 - 1] = '\0';
}

static inline int decode_base64(const char src[4])
{
	int val = 0;

	for (unsigned int i = 0; i < 4; ++i)
		val |= (-1
			    + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64))
			    + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70))
			    + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5))
			    + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63)
			    + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)
			) << (18 - 6 * i);
	return val;
}

bool key_from_base64(uint8_t key[static WG_KEY_LEN], const char *base64)
{
	unsigned int i;
	int val;

	if (strlen(base64) != WG_KEY_LEN_BASE64 - 1 || base64[WG_KEY_LEN_BASE64 - 2] != '=')
		return false;

	for (i = 0; i < WG_KEY_LEN / 3; ++i) {
		val = decode_base64(&base64[i * 4]);
		if (val < 0)
			return false;
		key[i * 3 + 0] = (val >> 16) & 0xff;
		key[i * 3 + 1] = (val >> 8) & 0xff;
		key[i * 3 + 2] = val & 0xff;
	}
	val = decode_base64((const char[]){ base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A' });
	if (val < 0 || val & 0xff)
		return false;
	key[i * 3 + 0] = (val >> 16) & 0xff;
	key[i * 3 + 1] = (val >> 8) & 0xff;
	return true;
}

void key_to_hex(char hex[static WG_KEY_LEN_HEX], const uint8_t key[static WG_KEY_LEN])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN; ++i) {
		hex[i * 2] = 87U + (key[i] >> 4) + ((((key[i] >> 4) - 10U) >> 8) & ~38U);
		hex[i * 2 + 1] = 87U + (key[i] & 0xf) + ((((key[i] & 0xf) - 10U) >> 8) & ~38U);
	}
	hex[i * 2] = '\0';
}

bool key_from_hex(uint8_t key[static WG_KEY_LEN], const char *hex)
{
	uint8_t c, c_acc = 0, c_alpha0, c_alpha, c_num0, c_num, c_val, state = 0;

	if (strlen(hex) != WG_KEY_LEN_HEX - 1)
		return false;

	for (unsigned int i = 0; i < WG_KEY_LEN_HEX - 1; ++i) {
		c = (uint8_t)hex[i];
		c_num = c ^ 48U;
		c_num0 = (c_num - 10U) >> 8;
		c_alpha = (c & ~32U) - 55U;
		c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
		if (!(c_num0 | c_alpha0))
			return false;
		c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
		if (!state)
			c_acc = c_val * 16U;
		else
			key[i / 2] = c_acc | c_val;
		state = ~state;
	}
	return true;
}

bool key_is_zero(const uint8_t key[static WG_KEY_LEN])
{
	volatile uint8_t acc = 0;

	for (unsigned int i = 0; i < WG_KEY_LEN; ++i) {
		acc |= key[i];
		__asm__ ("" : "=r" (acc) : "0" (acc));
	}
	return 1 & ((acc - 1) >> 8);
}
