/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef COMPAT_H
#define COMPAT_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
#error "WireGuard requires Linux >= 3.18"
#endif

/* These conditionals can't be enforced by an out of tree module very easily,
 * so we stick them here in compat instead. */
#if !IS_ENABLED(CONFIG_NETFILTER_XT_MATCH_HASHLIMIT)
#error "WireGuard requires CONFIG_NETFILTER_XT_MATCH_HASHLIMIT."
#endif
#if IS_ENABLED(CONFIG_IPV6) && !IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#error "WireGuard requires CONFIG_IP6_NF_IPTABLES when using CONFIG_IPV6."
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && !defined(DEBUG) && defined(net_dbg_ratelimited)
#undef net_dbg_ratelimited
#define net_dbg_ratelimited(fmt, ...) do { if (0) no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define RCU_LOCKDEP_WARN(cond, message) rcu_lockdep_assert(!(cond), message)
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 19, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 6)) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 12)
#define dev_recursion_level() 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#include <linux/if.h>
#include <net/udp_tunnel.h>
#define udp_tunnel_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) do { struct net_device *dev__ = (c)->dev; int ret__; ret__ = udp_tunnel_xmit_skb((b)->sk_socket, a, c, d, e, f, g, h, i, j, k); iptunnel_xmit_stats(ret__, &dev__->stats, dev__->tstats); } while (0)
#if IS_ENABLED(CONFIG_IPV6)
#define udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) udp_tunnel6_xmit_skb((b)->sk_socket, a, c, d, e, f, g, h, j, k);
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#include <linux/if.h>
#include <net/udp_tunnel.h>
static inline void fake_destructor(struct sk_buff *skb)
{
}
#define udp_tunnel_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) do { struct net_device *dev__ = (c)->dev; int ret__; (c)->destructor = fake_destructor; (c)->sk = (b); ret__ = udp_tunnel_xmit_skb(a, c, d, e, f, g, h, i, j, k, l); iptunnel_xmit_stats(ret__, &dev__->stats, dev__->tstats); } while (0)
#if IS_ENABLED(CONFIG_IPV6)
#define udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) do { (c)->destructor = fake_destructor; (c)->sk = (b); udp_tunnel6_xmit_skb(a, c, d, e, f, g, h, j, k, l); } while(0)
#endif
#else

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
#include <linux/if.h>
#include <net/udp_tunnel.h>
#define udp_tunnel_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) do { struct net_device *dev__ = (c)->dev; int ret__ = udp_tunnel_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l);  iptunnel_xmit_stats(ret__, &dev__->stats, dev__->tstats); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0) && IS_ENABLED(CONFIG_IPV6)
#include <linux/if.h>
#include <net/udp_tunnel.h>
#define udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, j, k, l)
#endif

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#include <linux/if.h>
#include <net/udp_tunnel.h>
struct udp_port_cfg_new {
	u8 family;
	union {
		struct in_addr local_ip;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr local_ip6;
#endif
	};
	union {
		struct in_addr peer_ip;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr peer_ip6;
#endif
	};
	__be16 local_udp_port;
	__be16 peer_udp_port;
	unsigned int use_udp_checksums:1, use_udp6_tx_checksums:1, use_udp6_rx_checksums:1, ipv6_v6only:1;
};
static inline int __maybe_unused udp_sock_create_new(struct net *net, struct udp_port_cfg_new *cfg, struct socket **sockp)
{
	struct udp_port_cfg old_cfg = {
		.family = cfg->family,
		.local_ip = cfg->local_ip,
#if IS_ENABLED(CONFIG_IPV6)
		.local_ip6 = cfg->local_ip6,
#endif
		.peer_ip = cfg->peer_ip,
#if IS_ENABLED(CONFIG_IPV6)
		.peer_ip6 = cfg->peer_ip6,
#endif
		.local_udp_port = cfg->local_udp_port,
		.peer_udp_port = cfg->peer_udp_port,
		.use_udp_checksums = cfg->use_udp_checksums,
		.use_udp6_tx_checksums = cfg->use_udp6_tx_checksums,
		.use_udp6_rx_checksums = cfg->use_udp6_rx_checksums
	};
	if (cfg->family == AF_INET)
		return udp_sock_create4(net, &old_cfg, sockp);

#if IS_ENABLED(CONFIG_IPV6)
	if (cfg->family == AF_INET6) {
		int ret;
		int old_bindv6only;
		struct net *nobns;

		if (cfg->ipv6_v6only) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
			nobns = &init_net;
#else
			nobns = net;
#endif
			/* Since udp_port_cfg only learned of ipv6_v6only in 4.3, we do this horrible
			 * hack here and set the sysctl variable temporarily to something that will
			 * set the right option for us in sock_create. It's super racey! */
			old_bindv6only = nobns->ipv6.sysctl.bindv6only;
			nobns->ipv6.sysctl.bindv6only = 1;
		}
		ret = udp_sock_create6(net, &old_cfg, sockp);
		if (cfg->ipv6_v6only)
			nobns->ipv6.sysctl.bindv6only = old_bindv6only;
		return ret;
	}
#endif
	return -EPFNOSUPPORT;
}
#define udp_port_cfg udp_port_cfg_new
#define udp_sock_create(a, b, c) udp_sock_create_new(a, b, c)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define ipv6_dst_lookup(a, b, c, d) ipv6_dst_lookup(b, c, d)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 5) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)) || (LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 17) && LINUX_VERSION_CODE > KERNEL_VERSION(3, 19, 0)) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 27)
#define IP6_ECN_set_ce(a, b) IP6_ECN_set_ce(b)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#define time_is_before_jiffies64(a) time_after64(get_jiffies_64(), a)
#define time_is_after_jiffies64(a) time_before64(get_jiffies_64(), a)
#define time_is_before_eq_jiffies64(a) time_after_eq64(get_jiffies_64(), a)
#define time_is_after_eq_jiffies64(a) time_before_eq64(get_jiffies_64(), a)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0) && IS_ENABLED(CONFIG_IPV6)
#include <net/addrconf.h>
static inline bool ipv6_mod_enabled(void)
{
	return ipv6_stub->udpv6_encap_enable != NULL;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#include <linux/skbuff.h>
static inline void skb_reset_tc(struct sk_buff *skb)
{
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = 0;
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#include <linux/siphash.h>
static inline u32 get_random_u32(void)
{
	static siphash_key_t key;
	static u32 counter = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
	static bool has_seeded = false;
	if (unlikely(!has_seeded)) {
		get_random_bytes(&key, sizeof(key));
		has_seeded = true;
	}
#else
	get_random_once(&key, sizeof(key));
#endif
	return siphash_2u32(counter++, get_random_int(), &key);
}
#endif

/* https://lkml.org/lkml/2015/6/12/415 */
#include <linux/netdevice.h>
static inline struct net_device *netdev_pub(void *dev)
{
	return (struct net_device *)((char *)dev - ALIGN(sizeof(struct net_device), NETDEV_ALIGN));
}

/* PaX compatibility */
#ifdef CONSTIFY_PLUGIN
#include <linux/cache.h>
#undef __read_mostly
#define __read_mostly
#endif

#if defined(CONFIG_DYNAMIC_DEBUG) || defined(DEBUG)
#define net_dbg_skb_ratelimited(fmt, skb, ...) do { \
	struct endpoint __endpoint; \
	socket_endpoint_from_skb(&__endpoint, skb); \
	net_dbg_ratelimited(fmt, &__endpoint.addr, ##__VA_ARGS__); \
} while(0)
#else
#define net_dbg_skb_ratelimited(fmt, skb, ...)
#endif

#endif
