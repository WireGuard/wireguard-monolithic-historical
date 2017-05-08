/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef COMPAT_H
#define COMPAT_H

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#error "WireGuard requires Linux >= 3.10"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#warning "WireGuard support for kernels < 4.1 should work but is slightly experimental."
#endif

/* These conditionals can't be enforced by an out of tree module very easily,
 * so we stick them here in compat instead. */
#if !IS_ENABLED(CONFIG_NETFILTER_XT_MATCH_HASHLIMIT)
#error "WireGuard requires CONFIG_NETFILTER_XT_MATCH_HASHLIMIT."
#endif
#if IS_ENABLED(CONFIG_IPV6) && !IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#error "WireGuard requires CONFIG_IP6_NF_IPTABLES when using CONFIG_IPV6."
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0) && defined(CONFIG_X86_64)
#define CONFIG_AS_SSSE3
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
#define headers_start data
#define headers_end data
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
#include "udp_tunnel/udp_tunnel_partial_compat.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && !defined(DEBUG) && defined(net_dbg_ratelimited)
#undef net_dbg_ratelimited
#define net_dbg_ratelimited(fmt, ...) do { if (0) no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define RCU_LOCKDEP_WARN(cond, message) rcu_lockdep_assert(!(cond), message)
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3, 19, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 6)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 12) && LINUX_VERSION_CODE > KERNEL_VERSION(3, 17, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 8) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)) || \
    LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 40)
#define dev_recursion_level() 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define ipv6_dst_lookup(a, b, c, d) ipv6_dst_lookup(b, c, d)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 5) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 17) && LINUX_VERSION_CODE > KERNEL_VERSION(3, 19, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 27) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 8) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 40) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)) || \
    (LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 54))

#include <linux/if.h>
#include <net/ip_tunnels.h>
#define IP6_ECN_set_ce(a, b) IP6_ECN_set_ce(b)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#define time_is_before_jiffies64(a) time_after64(get_jiffies_64(), a)
#define time_is_after_jiffies64(a) time_before64(get_jiffies_64(), a)
#define time_is_before_eq_jiffies64(a) time_after_eq64(get_jiffies_64(), a)
#define time_is_after_eq_jiffies64(a) time_before_eq64(get_jiffies_64(), a)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) && IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
struct ipv6_stub_type {
	void *udpv6_encap_enable;
	int (*ipv6_dst_lookup)(struct sock *sk, struct dst_entry **dst, struct flowi6 *fl6);
};
static const struct ipv6_stub_type ipv6_stub_impl = {
	.udpv6_encap_enable = (void *)1,
	.ipv6_dst_lookup = ip6_dst_lookup
};
static const struct ipv6_stub_type *ipv6_stub = &ipv6_stub_impl;
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
static inline void netif_keep_dst(struct net_device *dev)
{
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#define pcpu_sw_netstats pcpu_tstats
#define netdev_alloc_pcpu_stats alloc_percpu
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
#define netdev_alloc_pcpu_stats(type)					\
({									\
	typeof(type) __percpu *pcpu_stats = alloc_percpu(type);		\
	if (pcpu_stats)	{						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
#include "checksum/checksum_partial_compat.h"
static inline void *our_pskb_put(struct sk_buff *skb, struct sk_buff *tail, int len)
{
	if (tail != skb) {
		skb->data_len += len;
		skb->len += len;
	}
	return skb_put(tail, len);
}
#define pskb_put our_pskb_put
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
#include <net/xfrm.h>
static inline void skb_scrub_packet(struct sk_buff *skb, bool xnet)
{
#ifdef CONFIG_CAVIUM_OCTEON_IPFWD_OFFLOAD
	memset(&skb->cvm_info, 0, sizeof(skb->cvm_info));
	skb->cvm_reserved = 0;
#endif
	skb->tstamp.tv64 = 0;
	skb->pkt_type = PACKET_HOST;
	skb->skb_iif = 0;
	skb_dst_drop(skb);
	secpath_reset(skb);
	nf_reset(skb);
	nf_reset_trace(skb);
	if (!xnet)
		return;
	skb_orphan(skb);
	skb->mark = 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
#include <linux/random.h>
static inline u32 prandom_u32_max(u32 ep_ro)
{
	return (u32)(((u64) prandom_u32() * ep_ro) >> 32);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 75)
#define U8_MAX ((u8)~0U)
#define S8_MAX ((s8)(U8_MAX >> 1))
#define S8_MIN ((s8)(-S8_MAX - 1))
#define U16_MAX ((u16)~0U)
#define S16_MAX ((s16)(U16_MAX >> 1))
#define S16_MIN ((s16)(-S16_MAX - 1))
#define U32_MAX ((u32)~0U)
#define S32_MAX ((s32)(U32_MAX >> 1))
#define S32_MIN ((s32)(-S32_MAX - 1))
#define U64_MAX ((u64)~0ULL)
#define S64_MAX ((s64)(U64_MAX >> 1))
#define S64_MIN ((s64)(-S64_MAX - 1))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 60)
/* Making this static may very well invalidate its usefulness,
 * but so it goes with compat code. */
static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
	barrier();
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
static const struct in6_addr our_in6addr_any = IN6ADDR_ANY_INIT;
#define in6addr_any our_in6addr_any
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
