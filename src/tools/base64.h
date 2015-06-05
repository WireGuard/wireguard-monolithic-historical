/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef BASE64_H
#define BASE64_H

#include <resolv.h>

#define b64_len(len) ((((len) + 2) / 3) * 4 + 1)

#ifndef b64_ntop
int b64_ntop(unsigned char const *, size_t, char *, size_t);
#define NEED_B64_NTOP
#endif

#ifndef b64_pton
int b64_pton(char const *, unsigned char *, size_t);
#define NEED_B64_PTON
#endif

#endif
