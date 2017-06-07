/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "peer.h"
#include "device.h"
#include "packets.h"
#include "timers.h"
#include "hashtables.h"
#include "noise.h"

#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

static atomic64_t peer_counter = ATOMIC64_INIT(0);

static int choose_cpu(u64 id)
{
	unsigned int cpu, cpu_index, i;

	cpu_index = id % cpumask_weight(cpu_online_mask);
	cpu = cpumask_first(cpu_online_mask);
	for (i = 0; i < cpu_index; i += 1)
		cpu = cpumask_next(cpu, cpu_online_mask);

	return cpu;
}

struct wireguard_peer *peer_create(struct wireguard_device *wg, const u8 public_key[NOISE_PUBLIC_KEY_LEN], const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	struct wireguard_peer *peer;
	lockdep_assert_held(&wg->device_update_lock);

	if (peer_total_count(wg) >= MAX_PEERS_PER_DEVICE)
		return NULL;

	peer = kzalloc(sizeof(struct wireguard_peer), GFP_KERNEL);
	if (!peer)
		return NULL;

	if (dst_cache_init(&peer->endpoint_cache, GFP_KERNEL)) {
		kfree(peer);
		return NULL;
	}

	peer->internal_id = atomic64_inc_return(&peer_counter);
	peer->device = wg;
	cookie_init(&peer->latest_cookie);
	if (!noise_handshake_init(&peer->handshake, &wg->static_identity, public_key, preshared_key, peer)) {
		kfree(peer);
		return NULL;
	}
	cookie_checker_precompute_peer_keys(peer);
	mutex_init(&peer->keypairs.keypair_update_lock);
	INIT_WORK(&peer->transmit_handshake_work, packet_send_queued_handshakes);
	rwlock_init(&peer->endpoint_lock);
	kref_init(&peer->refcount);
	pubkey_hashtable_add(&wg->peer_hashtable, peer);
	list_add_tail(&peer->peer_list, &wg->peer_list);
	peer->work_cpu = choose_cpu(peer->internal_id);
	INIT_LIST_HEAD(&peer->init_queue.list);
	INIT_WORK(&peer->init_queue.work, packet_init_worker);
	INIT_LIST_HEAD(&peer->send_queue.list);
	INIT_WORK(&peer->send_queue.work, packet_send_worker);
	INIT_LIST_HEAD(&peer->receive_queue.list);
	INIT_WORK(&peer->receive_queue.work, packet_receive_worker);
	spin_lock_init(&peer->init_queue_lock);
	pr_debug("%s: Peer %Lu created\n", wg->dev->name, peer->internal_id);
	return peer;
}

struct wireguard_peer *peer_get(struct wireguard_peer *peer)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(), "Calling peer_get without holding the RCU read lock");
	if (unlikely(!peer || !kref_get_unless_zero(&peer->refcount)))
		return NULL;
	return peer;
}

struct wireguard_peer *peer_rcu_get(struct wireguard_peer *peer)
{
	rcu_read_lock_bh();
	peer = peer_get(peer);
	rcu_read_unlock_bh();
	return peer;
}

/* We have a separate "remove" function to get rid of the final reference because
 * peer_list, clearing handshakes, and flushing all require mutexes which requires
 * sleeping, which must only be done from certain contexts. */
void peer_remove(struct wireguard_peer *peer)
{
	if (unlikely(!peer))
		return;
	lockdep_assert_held(&peer->device->device_update_lock);
	noise_handshake_clear(&peer->handshake);
	noise_keypairs_clear(&peer->keypairs);
	list_del(&peer->peer_list);
	timers_uninit_peer(peer);
	routing_table_remove_by_peer(&peer->device->peer_routing_table, peer);
	pubkey_hashtable_remove(&peer->device->peer_hashtable, peer);
	flush_workqueue(peer->device->crypt_wq);
	if (peer->device->peer_wq)
		flush_workqueue(peer->device->peer_wq);
	peer_purge_queues(peer);
	peer_put(peer);
}

static void rcu_release(struct rcu_head *rcu)
{
	struct wireguard_peer *peer = container_of(rcu, struct wireguard_peer, rcu);
	pr_debug("%s: Peer %Lu (%pISpfsc) destroyed\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	dst_cache_destroy(&peer->endpoint_cache);
	kzfree(peer);
}

static void kref_release(struct kref *refcount)
{
	struct wireguard_peer *peer = container_of(refcount, struct wireguard_peer, refcount);
	call_rcu_bh(&peer->rcu, rcu_release);
}

void peer_put(struct wireguard_peer *peer)
{
	if (unlikely(!peer))
		return;
	kref_put(&peer->refcount, kref_release);
}

void peer_remove_all(struct wireguard_device *wg)
{
	struct wireguard_peer *peer, *temp;
	lockdep_assert_held(&wg->device_update_lock);
	list_for_each_entry_safe (peer, temp, &wg->peer_list, peer_list)
		peer_remove(peer);
}

unsigned int peer_total_count(struct wireguard_device *wg)
{
	unsigned int i = 0;
	struct wireguard_peer *peer;
	lockdep_assert_held(&wg->device_update_lock);
	list_for_each_entry (peer, &wg->peer_list, peer_list)
		++i;
	return i;
}
