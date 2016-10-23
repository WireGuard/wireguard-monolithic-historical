/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef COMPAT_H
#define COMPAT_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#error "WireGuard requires Linux >= 4.1"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && !defined(DEBUG) && defined(net_dbg_ratelimited)
#undef net_dbg_ratelimited
#define net_dbg_ratelimited(fmt, ...) do { if (0) no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
#include <linux/security.h>
#ifndef GRSECURITY_VERSION
#define get_random_long() (((u64)get_random_int() << 32) | get_random_int())
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define RCU_LOCKDEP_WARN(cond, message) rcu_lockdep_assert(!(cond), message)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
#include <linux/if.h>
#include <net/udp_tunnel.h>
#define udp_tunnel_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) do { int ret = udp_tunnel_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l);  iptunnel_xmit_stats(ret, &dev->stats, dev->tstats); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0) && IS_ENABLED(CONFIG_IPV6)
#include <linux/if.h>
#include <net/udp_tunnel.h>
#define udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, i, j, k, l) udp_tunnel6_xmit_skb(a, b, c, d, e, f, g, h, j, k, l)
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
__attribute__((unused)) static inline int udp_sock_create_new(struct net *net, struct udp_port_cfg_new *cfg, struct socket **sockp)
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 5) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)) || LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 17)
#define IP6_ECN_set_ce(a, b) IP6_ECN_set_ce(b)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#define time_is_before_jiffies64(a) time_after64(get_jiffies_64(), a)
#define time_is_after_jiffies64(a) time_before64(get_jiffies_64(), a)
#define time_is_before_eq_jiffies64(a) time_after_eq64(get_jiffies_64(), a)
#define time_is_after_eq_jiffies64(a) time_before_eq64(get_jiffies_64(), a)
#endif

/* https://lkml.org/lkml/2015/6/12/415 */
#include <linux/netdevice.h>
static inline struct net_device *netdev_pub(void *dev)
{
	return (struct net_device *)((char *)dev - ALIGN(sizeof(struct net_device), NETDEV_ALIGN));
}

/* https://lkml.org/lkml/2016/10/1/187 */
#ifdef CONFIG_WIREGUARD_PARALLEL
#include <linux/padata.h>
static inline int padata_queue_len(struct padata_instance *pinst)
{
	int len;
	rcu_read_lock_bh();
	len = atomic_read(&rcu_dereference_bh(pinst->pd)->refcnt);
	rcu_read_unlock_bh();
	return len;
}
#endif

/* PaX compatibility */
#ifdef CONSTIFY_PLUGIN
#include <linux/cache.h>
#undef __read_mostly
#define __read_mostly
#endif

#endif
