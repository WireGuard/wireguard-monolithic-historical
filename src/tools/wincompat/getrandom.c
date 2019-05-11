// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stdbool.h>
#include <ntsecapi.h>

static inline bool __attribute__((__warn_unused_result__)) get_random_bytes(uint8_t *out, size_t len)
{
	return RtlGenRandom(out, len);
}
