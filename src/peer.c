/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "timers.h"
#include "hashtables.h"
#include "noise.h"

#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

static atomic64_t peer_counter = ATOMIC64_INIT(0);

struct wireguard_peer *
peer_create(struct wireguard_device *wg,
	    const u8 public_key[NOISE_PUBLIC_KEY_LEN],
	    const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	struct wireguard_peer *peer;

	lockdep_assert_held(&wg->device_update_lock);

	if (wg->num_peers >= MAX_PEERS_PER_DEVICE)
		return NULL;

	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (unlikely(!peer))
		return NULL;
	peer->device = wg;

	if (!noise_handshake_init(&peer->handshake, &wg->static_identity,
				  public_key, preshared_key, peer))
		goto err_1;
	if (dst_cache_init(&peer->endpoint_cache, GFP_KERNEL))
		goto err_1;
	if (packet_queue_init(&peer->tx_queue, packet_tx_worker, false,
			      MAX_QUEUED_PACKETS))
		goto err_2;
	if (packet_queue_init(&peer->rx_queue, NULL, false, MAX_QUEUED_PACKETS))
		goto err_3;

	peer->internal_id = atomic64_inc_return(&peer_counter);
	peer->serial_work_cpu = nr_cpumask_bits;
	cookie_init(&peer->latest_cookie);
	timers_init(peer);
	cookie_checker_precompute_peer_keys(peer);
	spin_lock_init(&peer->keypairs.keypair_update_lock);
	INIT_WORK(&peer->transmit_handshake_work, packet_handshake_send_worker);
	rwlock_init(&peer->endpoint_lock);
	kref_init(&peer->refcount);
	skb_queue_head_init(&peer->staged_packet_queue);
	atomic64_set(&peer->last_sent_handshake,
		     ktime_get_boot_fast_ns() -
			     (u64)(REKEY_TIMEOUT + 1) * NSEC_PER_SEC);
	set_bit(NAPI_STATE_NO_BUSY_POLL, &peer->napi.state);
	netif_napi_add(wg->dev, &peer->napi, packet_rx_poll, NAPI_POLL_WEIGHT);
	napi_enable(&peer->napi);
	list_add_tail(&peer->peer_list, &wg->peer_list);
	pubkey_hashtable_add(&wg->peer_hashtable, peer);
	++wg->num_peers;
	pr_debug("%s: Peer %llu created\n", wg->dev->name, peer->internal_id);
	return peer;

err_3:
	packet_queue_free(&peer->tx_queue, false);
err_2:
	dst_cache_destroy(&peer->endpoint_cache);
err_1:
	kfree(peer);
	return NULL;
}

struct wireguard_peer *peer_get_maybe_zero(struct wireguard_peer *peer)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
			 "Taking peer reference without holding the RCU read lock");
	if (unlikely(!peer || !kref_get_unless_zero(&peer->refcount)))
		return NULL;
	return peer;
}

/* We have a separate "remove" function to get rid of the final reference
 * because peer_list, clearing handshakes, and flushing all require mutexes
 * which requires sleeping, which must only be done from certain contexts.
 */
void peer_remove(struct wireguard_peer *peer)
{
	if (unlikely(!peer))
		return;
	lockdep_assert_held(&peer->device->device_update_lock);

	/* Remove from configuration-time lookup structures so new packets
	 * can't enter.
	 */
	list_del_init(&peer->peer_list);
	allowedips_remove_by_peer(&peer->device->peer_allowedips, peer,
				  &peer->device->device_update_lock);
	pubkey_hashtable_remove(&peer->device->peer_hashtable, peer);

	/* Mark as dead, so that we don't allow jumping contexts after. */
	WRITE_ONCE(peer->is_dead, true);
	synchronize_rcu_bh();

	/* Now that no more keypairs can be created for this peer, we destroy
	 * existing ones.
	 */
	noise_keypairs_clear(&peer->keypairs);

	/* Destroy all ongoing timers that were in-flight at the beginning of
	 * this function.
	 */
	timers_stop(peer);

	/* The transition between packet encryption/decryption queues isn't
	 * guarded by is_dead, but each reference's life is strictly bounded by
	 * two generations: once for parallel crypto and once for serial
	 * ingestion, so we can simply flush twice, and be sure that we no
	 * longer have references inside these queues.
	 */

	/* a) For encrypt/decrypt. */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.1) For send (but not receive, since that's napi). */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.2.1) For receive (but not send, since that's wq). */
	napi_disable(&peer->napi);
	/* b.2.1) It's now safe to remove the napi struct, which must be done
	 * here from process context.
	 */
	netif_napi_del(&peer->napi);

	/* Ensure any workstructs we own (like transmit_handshake_work or
	 * clear_peer_work) no longer are in use.
	 */
	flush_workqueue(peer->device->handshake_send_wq);

	--peer->device->num_peers;
	peer_put(peer);
}

static void rcu_release(struct rcu_head *rcu)
{
	struct wireguard_peer *peer =
		container_of(rcu, struct wireguard_peer, rcu);
	dst_cache_destroy(&peer->endpoint_cache);
	packet_queue_free(&peer->rx_queue, false);
	packet_queue_free(&peer->tx_queue, false);
	kzfree(peer);
}

static void kref_release(struct kref *refcount)
{
	struct wireguard_peer *peer =
		container_of(refcount, struct wireguard_peer, refcount);
	pr_debug("%s: Peer %llu (%pISpfsc) destroyed\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr);
	/* Remove ourself from dynamic runtime lookup structures, now that the
	 * last reference is gone.
	 */
	index_hashtable_remove(&peer->device->index_hashtable,
			       &peer->handshake.entry);
	/* Remove any lingering packets that didn't have a chance to be
	 * transmitted.
	 */
	skb_queue_purge(&peer->staged_packet_queue);
	/* Free the memory used. */
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
