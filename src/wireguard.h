/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kconfig.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#error "WireGuard requires Linux >= 4.1"
#endif

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/net.h>
#include <linux/padata.h>

#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/siphash24.h"
#include "noise.h"
#include "routingtable.h"
#include "hashtables.h"
#include "peer.h"
#include "cookie.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0) && !defined(DEBUG) && defined(net_dbg_ratelimited)
#undef net_dbg_ratelimited
#define net_dbg_ratelimited(fmt, ...) do { if (0) no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
#define get_random_long() (((u64)get_random_int() << 32) | get_random_int())
#endif

struct wireguard_device {
	struct sock __rcu *sock4, *sock6;
	u16 incoming_port;
	struct net *creating_net;
	struct workqueue_struct *workqueue;
	struct workqueue_struct *parallelqueue;
	struct padata_instance *parallel_send, *parallel_receive;
	struct noise_static_identity static_identity;
	struct sk_buff_head incoming_handshakes;
	struct work_struct incoming_handshakes_work;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable peer_hashtable;
	struct index_hashtable index_hashtable;
	struct routing_table peer_routing_table;
	struct list_head peer_list;
	struct mutex device_update_lock;
	struct mutex socket_update_lock;
};

/* Inverse of netdev_priv in include/linux/netdevice.h
 * TODO: Try to get this function upstream, a la: https://lkml.org/lkml/2015/6/12/415 */
static inline struct net_device *netdev_pub(void *dev)
{
	return (struct net_device *)((char *)dev - ALIGN(sizeof(struct net_device), NETDEV_ALIGN));
}

/* 64-bit jiffy functions. See include/linux/jiffies.h for the 32 bit ones these resemble. */
static inline bool time_is_before_jiffies64(uint64_t a)
{
	return time_after64(get_jiffies_64(), a);
}
static inline bool time_is_after_jiffies64(uint64_t a)
{
	return time_before64(get_jiffies_64(), a);
}
static inline bool time_is_before_eq_jiffies64(uint64_t a)
{
	return time_after_eq64(get_jiffies_64(), a);
}
static inline bool time_is_after_eq_jiffies64(uint64_t a)
{
	return time_before_eq64(get_jiffies_64(), a);
}

#endif
