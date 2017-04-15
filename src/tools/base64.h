/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef BASE64_H
#define BASE64_H

#include <stdbool.h>
#include <stdint.h>
#include "../uapi.h"

#define WG_KEY_LEN_BASE64 ((((WG_KEY_LEN) + 2) / 3) * 4 + 1)

void key_to_base64(char base64[static WG_KEY_LEN_BASE64], const uint8_t key[static WG_KEY_LEN]);
bool key_from_base64(uint8_t key[static WG_KEY_LEN], const char *base64);

#endif
