/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef PEER_H
#define PEER_H

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
		struct in_addr src4;
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
	struct timer_list timer_retransmit_handshake, timer_send_keepalive, timer_new_handshake, timer_kill_ephemerals, timer_persistent_keepalive;
	unsigned int timer_handshake_attempts;
	unsigned long persistent_keepalive_interval;
	bool timers_enabled;
	bool timer_need_another_keepalive;
	bool need_resend_queue;
	bool sent_lastminute_handshake;
	struct timeval walltime_last_handshake;
	struct sk_buff_head tx_packet_queue;
	struct kref refcount;
	struct rcu_head rcu;
	struct list_head peer_list;
	u64 internal_id;
#ifdef CONFIG_WIREGUARD_PARALLEL
	atomic_t parallel_encryption_inflight;
#endif
};

struct wireguard_peer *peer_create(struct wireguard_device *wg, const u8 public_key[NOISE_PUBLIC_KEY_LEN]);

struct wireguard_peer *peer_get(struct wireguard_peer *peer);
struct wireguard_peer *peer_rcu_get(struct wireguard_peer *peer);

void peer_put(struct wireguard_peer *peer);
void peer_remove(struct wireguard_peer *peer);
void peer_remove_all(struct wireguard_device *wg);

struct wireguard_peer *peer_lookup_by_index(struct wireguard_device *wg, u32 index);

int peer_for_each_unlocked(struct wireguard_device *wg, int (*fn)(struct wireguard_peer *peer, void *ctx), void *data);
int peer_for_each(struct wireguard_device *wg, int (*fn)(struct wireguard_peer *peer, void *ctx), void *data);

unsigned int peer_total_count(struct wireguard_device *wg);

#endif
