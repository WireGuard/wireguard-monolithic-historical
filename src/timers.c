/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "wireguard.h"
#include "timers.h"
#include "packets.h"
#include "device.h"

enum {
	KEEPALIVE = 10 * HZ,
	MAX_TIMER_HANDSHAKES = (90 * HZ) / REKEY_TIMEOUT
};

/*
 * Timer for retransmitting the handshake if we don't hear back after `REKEY_TIMEOUT` ms
 * Timer for sending empty packet if we have received a packet but after have not sent one for `KEEPALIVE` ms
 * Timer for initiating new handshake if we have sent a packet but after have not received one (even empty) for `(KEEPALIVE + REKEY_TIMEOUT)` ms
 * Timer for zeroing out all ephemeral keys after `(REJECT_AFTER_TIME * 3)` ms if no new keys have been received
 * Timer for, if enabled, sending an empty authenticated packet every user-specified seconds
 */

/* This rounds the time down to the closest power of two of the closest quarter second. */
static inline unsigned long slack_time(unsigned long time)
{
	return time & ~(roundup_pow_of_two(HZ / 4) - 1);
}

static void expired_retransmit_handshake(unsigned long ptr)
{
	struct wireguard_peer *peer = (struct wireguard_peer *)ptr;

	pr_debug("Handshake for peer %Lu (%pISpfsc) did not complete after %d seconds, retrying\n", peer->internal_id, &peer->endpoint_addr, REKEY_TIMEOUT / HZ);
	if (peer->timer_handshake_attempts > MAX_TIMER_HANDSHAKES) {
		del_timer(&peer->timer_send_keepalive);
		/* We remove all existing packets and don't try again,
		 * if we try unsuccessfully for too long to make a handshake. */
		skb_queue_purge(&peer->tx_packet_queue);
		return;
	}
	packet_queue_send_handshake_initiation(peer);
	++peer->timer_handshake_attempts;
}

static void expired_send_keepalive(unsigned long ptr)
{
	struct wireguard_peer *peer = (struct wireguard_peer *)ptr;

	pr_debug("Sending keep alive packet to peer %Lu (%pISpfsc), since we received data, but haven't sent any for %d seconds\n", peer->internal_id, &peer->endpoint_addr, KEEPALIVE / HZ);
	packet_send_keepalive(peer);
	if (peer->timer_need_another_keepalive) {
		peer->timer_need_another_keepalive = false;
		mod_timer(&peer->timer_send_keepalive, jiffies + KEEPALIVE);
	}
}

static void expired_new_handshake(unsigned long ptr)
{
	struct wireguard_peer *peer = (struct wireguard_peer *)ptr;

	pr_debug("Retrying handshake with peer %Lu (%pISpfsc) because we stopped hearing back after %d seconds\n", peer->internal_id, &peer->endpoint_addr, (KEEPALIVE + REKEY_TIMEOUT) / HZ);
	packet_queue_send_handshake_initiation(peer);
}

static void expired_kill_ephemerals(unsigned long ptr)
{
	struct wireguard_peer *peer = (struct wireguard_peer *)ptr;

	rcu_read_lock();
	peer = peer_get(peer);
	rcu_read_unlock();
	if (!peer)
		return;

	if (!queue_work(peer->device->workqueue, &peer->clear_peer_work))
		peer_put(peer); /* If the work was already on the queue, we want to drop the extra reference */
}
static void queued_expired_kill_ephemerals(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, clear_peer_work);

	pr_debug("Zeroing out all keys for peer %Lu (%pISpfsc), since we haven't received a new one in %d seconds\n", peer->internal_id, &peer->endpoint_addr, (REJECT_AFTER_TIME * 3) / HZ);
	noise_handshake_clear(&peer->handshake);
	noise_keypairs_clear(&peer->keypairs);
	peer_put(peer);
}

static void expired_send_persistent_keepalive(unsigned long ptr)
{
	struct wireguard_peer *peer = (struct wireguard_peer *)ptr;

	if (unlikely(!peer->persistent_keepalive_interval))
		return;
	pr_debug("Sending keep alive packet to peer %Lu (%pISpfsc), since we haven't sent or received authenticated data for %lu seconds\n", peer->internal_id, &peer->endpoint_addr, peer->persistent_keepalive_interval / HZ);
	packet_send_keepalive(peer);
}

/* Should be called after an authenticated data packet is sent. */
void timers_data_sent(struct wireguard_peer *peer)
{
	if (likely(peer->timer_send_keepalive.data))
		del_timer(&peer->timer_send_keepalive);

	if (likely(peer->timer_new_handshake.data) && !timer_pending(&peer->timer_new_handshake))
		mod_timer(&peer->timer_new_handshake, jiffies + KEEPALIVE + REKEY_TIMEOUT);
}

/* Should be called after an authenticated data packet is received. */
void timers_data_received(struct wireguard_peer *peer)
{
	if (likely(peer->timer_send_keepalive.data) && !timer_pending(&peer->timer_send_keepalive))
		mod_timer(&peer->timer_send_keepalive, jiffies + KEEPALIVE);
	else
		peer->timer_need_another_keepalive = true;
}

/* Should be called after any type of authenticated packet is received -- keepalive or data. */
void timers_any_authenticated_packet_received(struct wireguard_peer *peer)
{
	if (likely(peer->timer_new_handshake.data))
		del_timer(&peer->timer_new_handshake);
}

/* Should be called after a handshake initiation message is sent. */
void timers_handshake_initiated(struct wireguard_peer *peer)
{
	if (likely(peer->timer_send_keepalive.data))
		del_timer(&peer->timer_send_keepalive);
	if (likely(peer->timer_retransmit_handshake.data))
		mod_timer(&peer->timer_retransmit_handshake, jiffies + REKEY_TIMEOUT);
}

/* Should be called after a handshake response message is received and processed. */
void timers_handshake_complete(struct wireguard_peer *peer)
{
	if (likely(peer->timer_retransmit_handshake.data))
		del_timer(&peer->timer_retransmit_handshake);
	peer->timer_handshake_attempts = 0;
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
void timers_ephemeral_key_created(struct wireguard_peer *peer)
{
	if (likely(peer->timer_kill_ephemerals.data))
		mod_timer(&peer->timer_kill_ephemerals, jiffies + (REJECT_AFTER_TIME * 3));
	do_gettimeofday(&peer->walltime_last_handshake);
}

/* Should be called before an packet with authentication -- data, keepalive, either handshake -- is sent, or after one is received. */
void timers_any_authenticated_packet_traversal(struct wireguard_peer *peer)
{
	if (peer->persistent_keepalive_interval && likely(peer->timer_persistent_keepalive.data))
		mod_timer(&peer->timer_persistent_keepalive, slack_time(jiffies + peer->persistent_keepalive_interval));
}

void timers_init_peer(struct wireguard_peer *peer)
{
	init_timer(&peer->timer_retransmit_handshake);
	peer->timer_retransmit_handshake.function = expired_retransmit_handshake;
	peer->timer_retransmit_handshake.data = (unsigned long)peer;

	init_timer(&peer->timer_send_keepalive);
	peer->timer_send_keepalive.function = expired_send_keepalive;
	peer->timer_send_keepalive.data = (unsigned long)peer;

	init_timer(&peer->timer_new_handshake);
	peer->timer_new_handshake.function = expired_new_handshake;
	peer->timer_new_handshake.data = (unsigned long)peer;

	init_timer(&peer->timer_kill_ephemerals);
	peer->timer_kill_ephemerals.function = expired_kill_ephemerals;
	peer->timer_kill_ephemerals.data = (unsigned long)peer;

	init_timer(&peer->timer_persistent_keepalive);
	peer->timer_persistent_keepalive.function = expired_send_persistent_keepalive;
	peer->timer_persistent_keepalive.data = (unsigned long)peer;

	INIT_WORK(&peer->clear_peer_work, queued_expired_kill_ephemerals);
}

void timers_uninit_peer(struct wireguard_peer *peer)
{
	if (peer->timer_retransmit_handshake.data) {
		del_timer(&peer->timer_retransmit_handshake);
		peer->timer_retransmit_handshake.data = 0;
	}
	if (peer->timer_send_keepalive.data) {
		del_timer(&peer->timer_send_keepalive);
		peer->timer_send_keepalive.data = 0;
	}
	if (peer->timer_new_handshake.data) {
		del_timer(&peer->timer_new_handshake);
		peer->timer_new_handshake.data = 0;
	}
	if (peer->timer_kill_ephemerals.data) {
		del_timer(&peer->timer_kill_ephemerals);
		peer->timer_kill_ephemerals.data = 0;
	}
	if (peer->timer_persistent_keepalive.data) {
		del_timer(&peer->timer_persistent_keepalive);
		peer->timer_persistent_keepalive.data = 0;
	}
}
void timers_uninit_peer_wait(struct wireguard_peer *peer)
{
	timers_uninit_peer(peer);
	flush_work(&peer->clear_peer_work);
}
