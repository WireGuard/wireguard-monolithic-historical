/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "timers.h"
#include "device.h"
#include "peer.h"
#include "packets.h"

/*
 * Timer for retransmitting the handshake if we don't hear back after `REKEY_TIMEOUT + jitter` ms
 * Timer for sending empty packet if we have received a packet but after have not sent one for `KEEPALIVE_TIMEOUT` ms
 * Timer for initiating new handshake if we have sent a packet but after have not received one (even empty) for `(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT)` ms
 * Timer for zeroing out all ephemeral keys after `(REJECT_AFTER_TIME * 3)` ms if no new keys have been received
 * Timer for, if enabled, sending an empty authenticated packet every user-specified seconds
 */

/* This rounds the time down to the closest power of two of the closest quarter second. */
static inline unsigned long slack_time(unsigned long time)
{
	return time & ~(roundup_pow_of_two(HZ / 4) - 1);
}

#define peer_get_from_ptr(ptr) \
	struct wireguard_peer *peer = peer_rcu_get((struct wireguard_peer *)ptr); \
	if (unlikely(!peer)) \
		return;

static void expired_retransmit_handshake(unsigned long ptr)
{
	peer_get_from_ptr(ptr);
	pr_debug("Handshake for peer %Lu (%pISpfsc) did not complete after %d seconds, retrying\n", peer->internal_id, &peer->endpoint.addr, REKEY_TIMEOUT / HZ);
	if (peer->timer_handshake_attempts > MAX_TIMER_HANDSHAKES) {
		del_timer(&peer->timer_send_keepalive);
		/* We remove all existing packets and don't try again,
		 * if we try unsuccessfully for too long to make a handshake. */
		skb_queue_purge(&peer->tx_packet_queue);
		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange. */
		if (likely(peer->timers_enabled))
			mod_timer(&peer->timer_kill_ephemerals, jiffies + (REJECT_AFTER_TIME * 3));
		goto out;
	}

	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	socket_clear_peer_endpoint_src(peer);

	packet_queue_handshake_initiation(peer);
	++peer->timer_handshake_attempts;
out:
	peer_put(peer);
}

static void expired_send_keepalive(unsigned long ptr)
{
	peer_get_from_ptr(ptr);
	packet_send_keepalive(peer);
	if (peer->timer_need_another_keepalive) {
		peer->timer_need_another_keepalive = false;
		if (peer->timers_enabled)
			mod_timer(&peer->timer_send_keepalive, jiffies + KEEPALIVE_TIMEOUT);
	}
	peer_put(peer);
}

static void expired_new_handshake(unsigned long ptr)
{
	peer_get_from_ptr(ptr);
	pr_debug("Retrying handshake with peer %Lu (%pISpfsc) because we stopped hearing back after %d seconds\n", peer->internal_id, &peer->endpoint.addr, (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) / HZ);
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	socket_clear_peer_endpoint_src(peer);
	packet_queue_handshake_initiation(peer);
	peer_put(peer);
}

static void expired_kill_ephemerals(unsigned long ptr)
{
	peer_get_from_ptr(ptr);
	if (!queue_work(peer->device->peer_wq, &peer->clear_peer_work)) /* Takes our reference. */
		peer_put(peer); /* If the work was already on the queue, we want to drop the extra reference */
}
static void queued_expired_kill_ephemerals(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, clear_peer_work);
	pr_debug("Zeroing out all keys for peer %Lu (%pISpfsc), since we haven't received a new one in %d seconds\n", peer->internal_id, &peer->endpoint.addr, (REJECT_AFTER_TIME * 3) / HZ);
	noise_handshake_clear(&peer->handshake);
	noise_keypairs_clear(&peer->keypairs);
	peer_put(peer);
}

static void expired_send_persistent_keepalive(unsigned long ptr)
{
	peer_get_from_ptr(ptr);
	if (likely(peer->persistent_keepalive_interval))
		packet_send_keepalive(peer);
	peer_put(peer);
}

/* Should be called after an authenticated data packet is sent. */
void timers_data_sent(struct wireguard_peer *peer)
{
	if (likely(peer->timers_enabled))
		del_timer(&peer->timer_send_keepalive);

	if (likely(peer->timers_enabled) && !timer_pending(&peer->timer_new_handshake))
		mod_timer(&peer->timer_new_handshake, jiffies + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
}

/* Should be called after an authenticated data packet is received. */
void timers_data_received(struct wireguard_peer *peer)
{
	if (likely(peer->timers_enabled) && !timer_pending(&peer->timer_send_keepalive))
		mod_timer(&peer->timer_send_keepalive, jiffies + KEEPALIVE_TIMEOUT);
	else
		peer->timer_need_another_keepalive = true;
}

/* Should be called after any type of authenticated packet is received -- keepalive or data. */
void timers_any_authenticated_packet_received(struct wireguard_peer *peer)
{
	if (likely(peer->timers_enabled))
		del_timer(&peer->timer_new_handshake);
}

/* Should be called after a handshake initiation message is sent. */
void timers_handshake_initiated(struct wireguard_peer *peer)
{
	if (likely(peer->timers_enabled)) {
		del_timer(&peer->timer_send_keepalive);
		mod_timer(&peer->timer_retransmit_handshake, slack_time(jiffies + REKEY_TIMEOUT + prandom_u32_max(REKEY_TIMEOUT_JITTER_MAX)));
	}
}

/* Should be called after a handshake response message is received and processed. */
void timers_handshake_complete(struct wireguard_peer *peer)
{
	if (likely(peer->timers_enabled))
		del_timer(&peer->timer_retransmit_handshake);
	peer->timer_handshake_attempts = 0;
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
void timers_ephemeral_key_created(struct wireguard_peer *peer)
{
	if (likely(peer->timers_enabled))
		mod_timer(&peer->timer_kill_ephemerals, jiffies + (REJECT_AFTER_TIME * 3));
	do_gettimeofday(&peer->walltime_last_handshake);
}

/* Should be called before an packet with authentication -- data, keepalive, either handshake -- is sent, or after one is received. */
void timers_any_authenticated_packet_traversal(struct wireguard_peer *peer)
{
	if (peer->persistent_keepalive_interval && likely(peer->timers_enabled))
		mod_timer(&peer->timer_persistent_keepalive, slack_time(jiffies + peer->persistent_keepalive_interval));
}

void timers_init_peer(struct wireguard_peer *peer)
{
	peer->timers_enabled = true;
	setup_timer(&peer->timer_retransmit_handshake, expired_retransmit_handshake, (unsigned long)peer);
	setup_timer(&peer->timer_send_keepalive, expired_send_keepalive, (unsigned long)peer);
	setup_timer(&peer->timer_new_handshake, expired_new_handshake, (unsigned long)peer);
	setup_timer(&peer->timer_kill_ephemerals, expired_kill_ephemerals, (unsigned long)peer);
	setup_timer(&peer->timer_persistent_keepalive, expired_send_persistent_keepalive, (unsigned long)peer);
	INIT_WORK(&peer->clear_peer_work, queued_expired_kill_ephemerals);
}

void timers_uninit_peer(struct wireguard_peer *peer)
{
	if (!peer->timers_enabled)
		return;
	peer->timers_enabled = false;
	wmb();
	del_timer_sync(&peer->timer_retransmit_handshake);
	del_timer_sync(&peer->timer_send_keepalive);
	del_timer_sync(&peer->timer_new_handshake);
	del_timer_sync(&peer->timer_kill_ephemerals);
	del_timer_sync(&peer->timer_persistent_keepalive);
	flush_work(&peer->clear_peer_work);
}
