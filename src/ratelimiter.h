/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef RATELIMITER_H
#define RATELIMITER_H

#include <linux/skbuff.h>

int ratelimiter_init(void);
void ratelimiter_uninit(void);
bool ratelimiter_allow(struct sk_buff *skb, struct net *net);

#endif
