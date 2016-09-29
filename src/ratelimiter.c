/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "ratelimiter.h"
#include "peer.h"
#include "device.h"

#include <linux/netfilter/x_tables.h>
#include <linux/module.h>
#include <net/ip.h>

#if !IS_ENABLED(CONFIG_NETFILTER_XT_MATCH_HASHLIMIT)
#error "WireGuard requires CONFIG_NETFILTER_XT_MATCH_HASHLIMIT."
#endif
#if IS_ENABLED(CONFIG_IPV6) && !IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#error "WireGuard requires CONFIG_IP6_NF_IPTABLES when using CONFIG_IPV6."
#endif

enum {
	RATELIMITER_PACKETS_PER_SECOND = 75,
	RATELIMITER_PACKETS_BURSTABLE = 5
};

static inline void cfg_init(struct hashlimit_cfg1 *cfg, int family)
{
	memset(cfg, 0, sizeof(struct hashlimit_cfg1));
	if (family == NFPROTO_IPV4)
		cfg->srcmask = 32;
	else if (family == NFPROTO_IPV6)
		cfg->srcmask = 96;
	cfg->mode = XT_HASHLIMIT_HASH_SIP; /* source IP only -- we could also do source port by ORing this with XT_HASHLIMIT_HASH_SPT */
	cfg->avg = XT_HASHLIMIT_SCALE / RATELIMITER_PACKETS_PER_SECOND; /* 75 per second per IP */
	cfg->burst = RATELIMITER_PACKETS_BURSTABLE; /* Allow bursts of 5 at a time */
	cfg->gc_interval = 1000; /* same as expiration date */
	cfg->expire = 1000; /* Units of avg (seconds = 1) times 1000 */
	/* cfg->size and cfg->max are computed based on the memory size of left to zero */
}

int ratelimiter_init(struct ratelimiter *ratelimiter, struct wireguard_device *wg)
{
	struct net_device *dev = netdev_pub(wg);
	struct xt_mtchk_param chk = { .net = wg->creating_net };
	int ret;

	memset(ratelimiter, 0, sizeof(struct ratelimiter));

	cfg_init(&ratelimiter->v4_info.cfg, NFPROTO_IPV4);
	cfg_init(&ratelimiter->v6_info.cfg, NFPROTO_IPV6);
	memcpy(ratelimiter->v4_info.name, dev->name, IFNAMSIZ);
	memcpy(ratelimiter->v6_info.name, dev->name, IFNAMSIZ);

	ratelimiter->v4_match = xt_request_find_match(NFPROTO_IPV4, "hashlimit", 1);
	if (IS_ERR(ratelimiter->v4_match)) {
		pr_err("The xt_hashlimit module for IPv4 is required");
		return PTR_ERR(ratelimiter->v4_match);
	}

	chk.matchinfo = &ratelimiter->v4_info;
	chk.match = ratelimiter->v4_match;
	chk.family = NFPROTO_IPV4;
	ret = ratelimiter->v4_match->checkentry(&chk);
	if (ret < 0) {
		module_put(ratelimiter->v4_match->me);
		return ret;
	}

#if IS_ENABLED(CONFIG_IPV6)
	ratelimiter->v6_match = xt_request_find_match(NFPROTO_IPV6, "hashlimit", 1);
	if (IS_ERR(ratelimiter->v6_match)) {
		pr_err("The xt_hashlimit module for IPv6 is required");
		module_put(ratelimiter->v4_match->me);
		return PTR_ERR(ratelimiter->v6_match);
	}

	chk.matchinfo = &ratelimiter->v6_info;
	chk.match = ratelimiter->v6_match;
	chk.family = NFPROTO_IPV6;
	ret = ratelimiter->v6_match->checkentry(&chk);
	if (ret < 0) {
		struct xt_mtdtor_param dtor_v4 = {
			.net = wg->creating_net,
			.match = ratelimiter->v4_match,
			.matchinfo = &ratelimiter->v4_info,
			.family = NFPROTO_IPV4
		};
		ratelimiter->v4_match->destroy(&dtor_v4);
		module_put(ratelimiter->v4_match->me);
		module_put(ratelimiter->v6_match->me);
		return ret;
	}
#endif

	ratelimiter->net = wg->creating_net;
	return 0;
}

void ratelimiter_uninit(struct ratelimiter *ratelimiter)
{
	struct xt_mtdtor_param dtor = { .net = ratelimiter->net };

	dtor.match = ratelimiter->v4_match;
	dtor.matchinfo = &ratelimiter->v4_info;
	dtor.family = NFPROTO_IPV4;
	ratelimiter->v4_match->destroy(&dtor);
	module_put(ratelimiter->v4_match->me);

#if IS_ENABLED(CONFIG_IPV6)
	dtor.match = ratelimiter->v6_match;
	dtor.matchinfo = &ratelimiter->v6_info;
	dtor.family = NFPROTO_IPV6;
	ratelimiter->v6_match->destroy(&dtor);
	module_put(ratelimiter->v6_match->me);
#endif
}

bool ratelimiter_allow(struct ratelimiter *ratelimiter, struct sk_buff *skb)
{
	struct xt_action_param action = { { NULL } };
	if (unlikely(skb->len < sizeof(struct iphdr)))
		return false;
	if (ip_hdr(skb)->version == 4) {
		action.match = ratelimiter->v4_match;
		action.matchinfo = &ratelimiter->v4_info;
		action.thoff = ip_hdrlen(skb);
		action.family = NFPROTO_IPV4;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (ip_hdr(skb)->version == 6) {
		action.match = ratelimiter->v6_match;
		action.matchinfo = &ratelimiter->v6_info;
		action.family = NFPROTO_IPV6;
	}
#endif
	else
		return false;
	return action.match->match(skb, &action);
}
