/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef RATELIMITER_H
#define RATELIMITER_H

#include <uapi/linux/netfilter/xt_hashlimit.h>

struct wireguard_device;
struct sk_buff;

struct ratelimiter {
	struct net *net;
	struct xt_hashlimit_mtinfo1 v4_info;
#if IS_ENABLED(CONFIG_IPV6)
	struct xt_hashlimit_mtinfo1 v6_info;
#endif
};

int ratelimiter_init(struct ratelimiter *ratelimiter, struct wireguard_device *wg);
void ratelimiter_uninit(struct ratelimiter *ratelimiter);
bool ratelimiter_allow(struct ratelimiter *ratelimiter, struct sk_buff *skb);

int ratelimiter_module_init(void);
void ratelimiter_module_deinit(void);

#endif
