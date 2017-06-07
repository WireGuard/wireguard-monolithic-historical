/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef PEER_H
#define PEER_H

#include "device.h"
#include "noise.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <net/dst_cache.h>

struct wireguard_device;

struct endpoint {
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	union {
		struct {
			struct in_addr src4;
			int src_if4; /* Essentially the same as addr6->scope_id */
		};
		struct in6_addr src6;
	};
};

struct wireguard_peer {
	struct wireguard_device *device;
	struct endpoint endpoint;
	struct dst_cache endpoint_cache;
	rwlock_t endpoint_lock;
	struct noise_handshake handshake;
	struct noise_keypairs keypairs;
	u64 last_sent_handshake;
	struct work_struct transmit_handshake_work, clear_peer_work;
	struct cookie latest_cookie;
	struct hlist_node pubkey_hash;
	u64 rx_bytes, tx_bytes;
	struct timer_list timer_retransmit_handshake, timer_send_keepalive, timer_new_handshake, timer_zero_key_material, timer_persistent_keepalive;
	unsigned int timer_handshake_attempts;
	unsigned long persistent_keepalive_interval;
	bool timers_enabled;
	bool timer_need_another_keepalive;
	bool sent_lastminute_handshake;
	struct timeval walltime_last_handshake;
	struct kref refcount;
	struct rcu_head rcu;
	struct list_head peer_list;
	u64 internal_id;
	int work_cpu;
	struct crypt_queue init_queue, send_queue, receive_queue;
	spinlock_t init_queue_lock;
};

struct wireguard_peer *peer_create(struct wireguard_device *wg, const u8 public_key[NOISE_PUBLIC_KEY_LEN], const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

struct wireguard_peer *peer_get(struct wireguard_peer *peer);
struct wireguard_peer *peer_rcu_get(struct wireguard_peer *peer);

void peer_put(struct wireguard_peer *peer);
void peer_remove(struct wireguard_peer *peer);
void peer_remove_all(struct wireguard_device *wg);

struct wireguard_peer *peer_lookup_by_index(struct wireguard_device *wg, u32 index);

unsigned int peer_total_count(struct wireguard_device *wg);

/* This is a macro iterator of essentially this:
 *
 * if (__should_lock)
 *	mutex_lock(&(__wg)->device_update_lock);
 * else
 *	lockdep_assert_held(&(__wg)->device_update_lock)
 * list_for_each_entry_safe (__peer, __temp, &(__wg)->peer_list, peer_list) {
 *	__peer = peer_rcu_get(__peer);
 *	if (!__peer)
 *		continue;
 *	ITERATOR_BODY
 *	peer_put(__peer);
 * }
 * if (__should_lock)
 *	mutex_unlock(&(__wg)->device_update_lock);
 *
 * While it's really ugly to look at, the code gcc produces from it is actually perfect.
 */
#define pfe_label(n) __PASTE(__PASTE(pfe_label_, n ## _), __LINE__)
#define peer_for_each(__wg, __peer, __temp, __should_lock) \
	if (1) { if (__should_lock) mutex_lock(&(__wg)->device_update_lock); else lockdep_assert_held(&(__wg)->device_update_lock); goto pfe_label(1); } else pfe_label(1): \
	if (1) goto pfe_label(2); else while (1) if (1) { if (__should_lock) mutex_unlock(&(__wg)->device_update_lock); break; } else pfe_label(2): \
	list_for_each_entry_safe (__peer, __temp, &(__wg)->peer_list, peer_list) \
	if (0) pfe_label(3): break; else \
	if (0); else for (__peer = peer_rcu_get(peer); __peer;) if (1) { goto pfe_label(4); pfe_label(5): break; } else while (1) if (1) goto pfe_label(5); else pfe_label(4): \
	if (1) { goto pfe_label(6); pfe_label(7):; } else while (1) if (1) goto pfe_label(3); else while (1) if (1) goto pfe_label(7); else pfe_label(6): \
	if (1) { goto pfe_label(8); pfe_label(9): peer_put(__peer); break; pfe_label(10): peer_put(__peer); } else while (1) if (1) goto pfe_label(9); else while (1) if (1) goto pfe_label(10); else pfe_label(8):

#endif
