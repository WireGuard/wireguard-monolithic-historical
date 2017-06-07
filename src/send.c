/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "packets.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
#include "queue.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/jiffies.h>
#include <net/udp.h>
#include <net/sock.h>

static void packet_send_handshake_initiation(struct wireguard_peer *peer)
{
	struct message_handshake_initiation packet;

	down_write(&peer->handshake.lock);
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT)) {
		up_write(&peer->handshake.lock);
		return; /* This function is rate limited. */
	}
	peer->last_sent_handshake = get_jiffies_64();
	up_write(&peer->handshake.lock);

	net_dbg_ratelimited("%s: Sending handshake initiation to peer %Lu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);

	if (noise_handshake_create_initiation(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		timers_any_authenticated_packet_traversal(peer);
		socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_initiation), HANDSHAKE_DSCP);
		timers_handshake_initiated(peer);
	}
}

void packet_send_queued_handshakes(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, transmit_handshake_work);
	packet_send_handshake_initiation(peer);
	peer_put(peer);
}

void packet_queue_handshake_initiation(struct wireguard_peer *peer, bool is_retry)
{
	if (!is_retry)
		peer->timer_handshake_attempts = 0;

	/* First checking the timestamp here is just an optimization; it will
	 * be caught while properly locked inside the actual work queue. */
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT))
		return;

	peer = peer_rcu_get(peer);
	if (unlikely(!peer))
		return;

	/* Queues up calling packet_send_queued_handshakes(peer), where we do a peer_put(peer) after: */
	if (!queue_work(peer->device->peer_wq, &peer->transmit_handshake_work))
		peer_put(peer); /* If the work was already queued, we want to drop the extra reference */
}

void packet_send_handshake_response(struct wireguard_peer *peer)
{
	struct message_handshake_response packet;

	net_dbg_ratelimited("%s: Sending handshake response to peer %Lu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	peer->last_sent_handshake = get_jiffies_64();

	if (noise_handshake_create_response(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (noise_handshake_begin_session(&peer->handshake, &peer->keypairs)) {
			timers_session_derived(peer);
			timers_any_authenticated_packet_traversal(peer);
			socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_response), HANDSHAKE_DSCP);
		}
	}
}

void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index)
{
	struct message_handshake_cookie packet;

	net_dbg_skb_ratelimited("%s: Sending cookie response for denied handshake message for %pISpfsc\n", wg->dev->name, initiating_skb);
	cookie_message_create(&packet, initiating_skb, sender_index, &wg->cookie_checker);
	socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet, sizeof(packet));
}

void keep_key_fresh_send(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	bool send = false;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	if (likely(keypair && keypair->sending.is_valid) &&
	   (unlikely(atomic64_read(&keypair->sending.counter.counter) > REKEY_AFTER_MESSAGES) ||
	   (keypair->i_am_the_initiator && unlikely(time_is_before_eq_jiffies64(keypair->sending.birthdate + REKEY_AFTER_TIME)))))
		send = true;
	rcu_read_unlock_bh();

	if (send)
		packet_queue_handshake_initiation(peer, false);
}

void packet_send_keepalive(struct wireguard_peer *peer)
{
	struct sk_buff *skb;
	struct sk_buff_head queue;

	if (queue_empty(&peer->init_queue)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH, GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = peer->device->dev;
		__skb_queue_head_init(&queue);
		__skb_queue_tail(&queue, skb);
		packet_create_data(peer, &queue);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %Lu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	} else {
		/* There are packets pending which need to be initialized with the new keypair. */
		queue_work(peer->device->crypt_wq, &peer->init_queue.work);
	}
}
