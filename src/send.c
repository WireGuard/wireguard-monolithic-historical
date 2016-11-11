/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "packets.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
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

	net_dbg_ratelimited("Sending handshake initiation to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr_storage);

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

void packet_queue_handshake_initiation(struct wireguard_peer *peer)
{
	/* First checking the timestamp here is just an optimization; it will
	 * be caught while properly locked inside the actual work queue. */
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT))
		return;

	peer = peer_rcu_get(peer);
	if (unlikely(!peer))
		return;

	/* Queues up calling packet_send_queued_handshakes(peer), where we do a peer_put(peer) after: */
	if (!queue_work(peer->device->workqueue, &peer->transmit_handshake_work))
		peer_put(peer); /* If the work was already queued, we want to drop the extra reference */
}

void packet_send_handshake_response(struct wireguard_peer *peer)
{
	struct message_handshake_response packet;

	net_dbg_ratelimited("Sending handshake response to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr_storage);
	peer->last_sent_handshake = get_jiffies_64();

	if (noise_handshake_create_response(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (noise_handshake_begin_session(&peer->handshake, &peer->keypairs, false)) {
			timers_ephemeral_key_created(peer);
			timers_any_authenticated_packet_traversal(peer);
			socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_response), HANDSHAKE_DSCP);
		}
	}
}

void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, void *data, size_t data_len, __le32 sender_index)
{
	struct message_handshake_cookie packet;

	net_dbg_skb_ratelimited("Sending cookie response for denied handshake message for %pISpfsc\n", initiating_skb);
	cookie_message_create(&packet, initiating_skb, data, data_len, sender_index, &wg->cookie_checker);
	socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet, sizeof(packet));
}

static inline void keep_key_fresh(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	bool send = false;

	rcu_read_lock();
	keypair = rcu_dereference(peer->keypairs.current_keypair);
	if (likely(keypair && keypair->sending.is_valid) &&
	   (unlikely(atomic64_read(&keypair->sending.counter.counter) > REKEY_AFTER_MESSAGES) ||
	   (keypair->i_am_the_initiator && unlikely(time_is_before_eq_jiffies64(keypair->sending.birthdate + REKEY_AFTER_TIME)))))
		send = true;
	rcu_read_unlock();

	if (send)
		packet_queue_handshake_initiation(peer);
}

void packet_send_keepalive(struct wireguard_peer *peer)
{
	struct sk_buff *skb;
	if (!skb_queue_len(&peer->tx_packet_queue)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH, GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = netdev_pub(peer->device);
		skb_queue_tail(&peer->tx_packet_queue, skb);
		net_dbg_ratelimited("Sending keepalive packet to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr_storage);
	}
	packet_send_queue(peer);
}

static void message_create_data_done(struct sk_buff_head *queue, struct wireguard_peer *peer)
{
	struct sk_buff *skb, *tmp;
	bool is_keepalive, data_sent = false;

	timers_any_authenticated_packet_traversal(peer);
	skb_queue_walk_safe(queue, skb, tmp) {
		is_keepalive = skb->len == message_data_len(0);
		if (likely(!socket_send_skb_to_peer(peer, skb, *(u8 *)skb->cb) && !is_keepalive))
			data_sent = true;
	}
	if (likely(data_sent))
		timers_data_sent(peer);

	keep_key_fresh(peer);

	if (unlikely(peer->need_resend_queue))
		packet_send_queue(peer);
}

int packet_send_queue(struct wireguard_peer *peer)
{
	struct sk_buff_head queue;
	unsigned long flags;

	peer->need_resend_queue = false;

	/* Steal the current queue into our local one. */
	skb_queue_head_init(&queue);
	spin_lock_irqsave(&peer->tx_packet_queue.lock, flags);
	skb_queue_splice_init(&peer->tx_packet_queue, &queue);
	spin_unlock_irqrestore(&peer->tx_packet_queue.lock, flags);

	if (unlikely(!skb_queue_len(&queue)))
		return NETDEV_TX_OK;

	/* We submit it for encryption and sending. */
	switch (packet_create_data(&queue, peer, message_create_data_done)) {
	case 0:
		break;
	case -ENOKEY:
		/* ENOKEY means that we don't have a valid session for the peer, which
		 * means we should initiate a session, and then requeue everything. */
		packet_queue_handshake_initiation(peer);
		goto requeue;
	case -EBUSY:
		/* EBUSY happens when the parallel workers are all filled up, in which
		 * case we should requeue everything. */

		/* First, we mark that we should try to do this later, when existing
		 * jobs are done. */
		peer->need_resend_queue = true;
	requeue:
		/* We stick the remaining skbs from local_queue at the top of the peer's
		 * queue again, setting the top of local_queue to be the skb that begins
		 * the requeueing. */
		spin_lock_irqsave(&peer->tx_packet_queue.lock, flags);
		skb_queue_splice(&queue, &peer->tx_packet_queue);
		spin_unlock_irqrestore(&peer->tx_packet_queue.lock, flags);
		break;
	default:
		/* If we failed for any other reason, we want to just free the packets and
		 * forget about them. We do this unlocked, since we're the only ones with
		 * a reference to the local queue. */
		__skb_queue_purge(&queue);
	}
	return NETDEV_TX_OK;
}
