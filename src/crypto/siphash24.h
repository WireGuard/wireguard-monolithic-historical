/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef SIPHASH24_H
#define SIPHASH24_H

#include <linux/types.h>

enum siphash24_lengths {
	SIPHASH24_KEY_LEN = 16
};

uint64_t siphash24(const uint8_t *data, size_t len, const uint8_t key[SIPHASH24_KEY_LEN]);

#ifdef DEBUG
bool siphash24_selftest(void);
#endif

#endif
