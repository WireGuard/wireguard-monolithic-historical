/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef SIPHASH24_H
#define SIPHASH24_H

#include <linux/types.h>

enum siphash24_lengths {
	SIPHASH24_KEY_LEN = 16
};

u64 siphash24(const u8 *data, size_t len, const u8 key[SIPHASH24_KEY_LEN]);

#ifdef DEBUG
bool siphash24_selftest(void);
#endif

#endif
