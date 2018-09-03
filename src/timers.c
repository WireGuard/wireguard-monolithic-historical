/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "timers.h"
#include "device.h"
#include "peer.h"
#include "queueing.h"
#include "socket.h"

/*
 * - Timer for retransmitting the handshake if we don't hear back after
 * `REKEY_TIMEOUT + jitter` ms.
 *
 * - Timer for sending empty packet if we have received a packet but after have
 * not sent one for `KEEPALIVE_TIMEOUT` ms.
 *
 * - Timer for initiating new handshake if we have sent a packet but after have
 * not received one (even empty) for `(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)` ms.
 *
 * - Timer for zeroing out all ephemeral keys after `(REJECT_AFTER_TIME * 3)` ms
 * if no new keys have been received.
 *
 * - Timer for, if enabled, sending an empty authenticated packet every user-
 * specified seconds.
 */

#define peer_get_from_timer(timer_name)                                        \
	struct wireguard_peer *peer;                                           \
	rcu_read_lock_bh();                                                    \
	peer = peer_get_maybe_zero(from_timer(peer, timer, timer_name));       \
	rcu_read_unlock_bh();                                                  \
	if (unlikely(!peer))                                                   \
		return;

static inline void mod_peer_timer(struct wireguard_peer *peer,
				  struct timer_list *timer,
				  unsigned long expires)
{
	rcu_read_lock_bh();
	if (likely(netif_running(peer->device->dev) && !peer->is_dead))
		mod_timer(timer, expires);
	rcu_read_unlock_bh();
}

static inline void del_peer_timer(struct wireguard_peer *peer,
				  struct timer_list *timer)
{
	rcu_read_lock_bh();
	if (likely(netif_running(peer->device->dev) && !peer->is_dead))
		del_timer(timer);
	rcu_read_unlock_bh();
}

static void expired_retransmit_handshake(struct timer_list *timer)
{
	peer_get_from_timer(timer_retransmit_handshake);

	if (peer->timer_handshake_attempts > MAX_TIMER_HANDSHAKES) {
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d attempts, giving up\n",
			 peer->device->dev->name, peer->internal_id,
			 &peer->endpoint.addr, MAX_TIMER_HANDSHAKES + 2);

		del_peer_timer(peer, &peer->timer_send_keepalive);
		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		skb_queue_purge(&peer->staged_packet_queue);

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if (!timer_pending(&peer->timer_zero_key_material))
			mod_peer_timer(peer, &peer->timer_zero_key_material,
				       jiffies + REJECT_AFTER_TIME * 3 * HZ);
	} else {
		++peer->timer_handshake_attempts;
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d seconds, retrying (try %d)\n",
			 peer->device->dev->name, peer->internal_id,
			 &peer->endpoint.addr, REKEY_TIMEOUT,
			 peer->timer_handshake_attempts + 1);

		/* We clear the endpoint address src address, in case this is
		 * the cause of trouble.
		 */
		socket_clear_peer_endpoint_src(peer);

		packet_send_queued_handshake_initiation(peer, true);
	}
	peer_put(peer);
}

static void expired_send_keepalive(struct timer_list *timer)
{
	peer_get_from_timer(timer_send_keepalive);

	packet_send_keepalive(peer);
	if (peer->timer_need_another_keepalive) {
		peer->timer_need_another_keepalive = false;
		mod_peer_timer(peer, &peer->timer_send_keepalive,
			       jiffies + KEEPALIVE_TIMEOUT * HZ);
	}
	peer_put(peer);
}

static void expired_new_handshake(struct timer_list *timer)
{
	peer_get_from_timer(timer_new_handshake);

	pr_debug("%s: Retrying handshake with peer %llu (%pISpfsc) because we stopped hearing back after %d seconds\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr, KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
	/* We clear the endpoint address src address, in case this is the cause
	 * of trouble.
	 */
	socket_clear_peer_endpoint_src(peer);
	packet_send_queued_handshake_initiation(peer, false);
	peer_put(peer);
}

static void expired_zero_key_material(struct timer_list *timer)
{
	peer_get_from_timer(timer_zero_key_material);

	rcu_read_lock_bh();
	if (!peer->is_dead) {
		 /* Should take our reference. */
		if (!queue_work(peer->device->handshake_send_wq,
				&peer->clear_peer_work))
			/* If the work was already on the queue, we want to drop the extra reference */
			peer_put(peer);
	}
	rcu_read_unlock_bh();
}
static void queued_expired_zero_key_material(struct work_struct *work)
{
	struct wireguard_peer *peer =
		container_of(work, struct wireguard_peer, clear_peer_work);

	pr_debug("%s: Zeroing out all keys for peer %llu (%pISpfsc), since we haven't received a new one in %d seconds\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr, REJECT_AFTER_TIME * 3);
	noise_handshake_clear(&peer->handshake);
	noise_keypairs_clear(&peer->keypairs);
	peer_put(peer);
}

static void expired_send_persistent_keepalive(struct timer_list *timer)
{
	peer_get_from_timer(timer_persistent_keepalive);

	if (likely(peer->persistent_keepalive_interval))
		packet_send_keepalive(peer);
	peer_put(peer);
}

/* Should be called after an authenticated data packet is sent. */
void timers_data_sent(struct wireguard_peer *peer)
{
	if (!timer_pending(&peer->timer_new_handshake))
		mod_peer_timer(peer, &peer->timer_new_handshake,
			jiffies + (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * HZ);
}

/* Should be called after an authenticated data packet is received. */
void timers_data_received(struct wireguard_peer *peer)
{
	if (likely(netif_running(peer->device->dev))) {
		if (!timer_pending(&peer->timer_send_keepalive))
			mod_peer_timer(peer, &peer->timer_send_keepalive,
				       jiffies + KEEPALIVE_TIMEOUT * HZ);
		else
			peer->timer_need_another_keepalive = true;
	}
}

/* Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
void timers_any_authenticated_packet_sent(struct wireguard_peer *peer)
{
	del_peer_timer(peer, &peer->timer_send_keepalive);
}

/* Should be called after any type of authenticated packet is received, whether
 * keepalive, data, or handshake.
 */
void timers_any_authenticated_packet_received(struct wireguard_peer *peer)
{
	del_peer_timer(peer, &peer->timer_new_handshake);
}

/* Should be called after a handshake initiation message is sent. */
void timers_handshake_initiated(struct wireguard_peer *peer)
{
	mod_peer_timer(
		peer, &peer->timer_retransmit_handshake,
		jiffies + REKEY_TIMEOUT * HZ +
			prandom_u32_max(REKEY_TIMEOUT_JITTER_MAX_JIFFIES));
}

/* Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
void timers_handshake_complete(struct wireguard_peer *peer)
{
	del_peer_timer(peer, &peer->timer_retransmit_handshake);
	peer->timer_handshake_attempts = 0;
	peer->sent_lastminute_handshake = false;
	getnstimeofday(&peer->walltime_last_handshake);
}

/* Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
void timers_session_derived(struct wireguard_peer *peer)
{
	mod_peer_timer(peer, &peer->timer_zero_key_material,
		       jiffies + REJECT_AFTER_TIME * 3 * HZ);
}

/* Should be called before a packet with authentication, whether
 * keepalive, data, or handshakem is sent, or after one is received.
 */
void timers_any_authenticated_packet_traversal(struct wireguard_peer *peer)
{
	if (peer->persistent_keepalive_interval)
		mod_peer_timer(peer, &peer->timer_persistent_keepalive,
			jiffies + peer->persistent_keepalive_interval * HZ);
}

void timers_init(struct wireguard_peer *peer)
{
	timer_setup(&peer->timer_retransmit_handshake,
		    expired_retransmit_handshake, 0);
	timer_setup(&peer->timer_send_keepalive, expired_send_keepalive, 0);
	timer_setup(&peer->timer_new_handshake, expired_new_handshake, 0);
	timer_setup(&peer->timer_zero_key_material, expired_zero_key_material, 0);
	timer_setup(&peer->timer_persistent_keepalive,
		    expired_send_persistent_keepalive, 0);
	INIT_WORK(&peer->clear_peer_work, queued_expired_zero_key_material);
	peer->timer_handshake_attempts = 0;
	peer->sent_lastminute_handshake = false;
	peer->timer_need_another_keepalive = false;
}

void timers_stop(struct wireguard_peer *peer)
{
	del_timer_sync(&peer->timer_retransmit_handshake);
	del_timer_sync(&peer->timer_send_keepalive);
	del_timer_sync(&peer->timer_new_handshake);
	del_timer_sync(&peer->timer_zero_key_material);
	del_timer_sync(&peer->timer_persistent_keepalive);
	flush_work(&peer->clear_peer_work);
}
