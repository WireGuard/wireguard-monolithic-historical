/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "wireguard.h"
#include "packets.h"
#include "timers.h"
#include "device.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"
#include <net/udp.h>
#include <net/sock.h>
#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/jiffies.h>

void packet_send_handshake_initiation(struct wireguard_peer *peer)
{
	struct message_handshake_initiation packet;

	net_dbg_ratelimited("Sending handshake initiation to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint_addr);
	peer->last_sent_handshake = get_jiffies_64();

	if (noise_handshake_create_initiation(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_initiation), HANDSHAKE_DSCP);
		timers_handshake_initiated(peer);
	}
}

void packet_send_handshake_response(struct wireguard_peer *peer)
{
	struct message_handshake_response packet;

	net_dbg_ratelimited("Sending handshake response to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint_addr);
	peer->last_sent_handshake = get_jiffies_64();

	if (noise_handshake_create_response(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (noise_handshake_begin_session(&peer->handshake, &peer->keypairs, false)) {
			timers_ephemeral_key_created(peer);
			socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_response), HANDSHAKE_DSCP);
		}
	}
}

void packet_send_queued_handshakes(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, transmit_handshake_work);
	peer->last_sent_handshake = get_jiffies_64();
	packet_send_handshake_initiation(peer);
	peer_put(peer);
}

void packet_queue_send_handshake_initiation(struct wireguard_peer *peer)
{
	rcu_read_lock();
	peer = peer_get(peer);
	rcu_read_unlock();
	if (!peer)
		return;
	/* Queues up calling packet_send_queued_handshakes(peer), where we do a peer_put(peer) after: */
	if (!queue_work(peer->device->workqueue, &peer->transmit_handshake_work))
		peer_put(peer); /* If the work was already queued, we want to drop the extra reference */
}

static inline void ratelimit_packet_send_handshake_initiation(struct wireguard_peer *peer)
{
	if (time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT))
		packet_queue_send_handshake_initiation(peer);
}

void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, void *data, size_t data_len, __le32 sender_index)
{
	struct message_handshake_cookie packet;

#ifdef DEBUG
	struct sockaddr_storage addr = { 0 };
	if (initiating_skb)
		socket_addr_from_skb(&addr, initiating_skb);
	net_dbg_ratelimited("Sending cookie response for denied handshake message for %pISpfsc\n", &addr);
#endif
	cookie_message_create(&packet, initiating_skb, data, data_len, sender_index, &wg->cookie_checker);
	socket_send_buffer_as_reply_to_skb(initiating_skb, &packet, sizeof(packet), wg);
}

static inline void keep_key_fresh(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	unsigned long rekey_after_time = REKEY_AFTER_TIME;

	rcu_read_lock();
	keypair = rcu_dereference(peer->keypairs.current_keypair);
	if (unlikely(!keypair || !keypair->sending.is_valid)) {
		rcu_read_unlock();
		return;
	}

	/* We don't want both peers initiating a new handshake at the same time */
	if (!keypair->i_am_the_initiator)
		rekey_after_time += REKEY_TIMEOUT * 2;

	if (atomic64_read(&keypair->sending.counter.counter) > REKEY_AFTER_MESSAGES ||
	    time_is_before_eq_jiffies64(keypair->sending.birthdate + rekey_after_time)) {
		rcu_read_unlock();
		ratelimit_packet_send_handshake_initiation(peer);
	} else
		rcu_read_unlock();
}

void packet_send_keepalive(struct wireguard_peer *peer)
{
	struct sk_buff *skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH, GFP_ATOMIC);
	if (unlikely(!skb))
		return;
	skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
	skb->dev = netdev_pub(peer->device);
	skb_queue_tail(&peer->tx_packet_queue, skb);
	packet_send_queue(peer);
}

struct packet_bundle {
	atomic_t count;
	struct sk_buff *first;
};

static inline void send_off_bundle(struct packet_bundle *bundle, struct wireguard_peer *peer)
{
	struct sk_buff *skb, *next;
	bool is_keepalive;
	for (skb = bundle->first; skb; skb = next) {
		/* We store the next pointer locally because socket_send_skb_to_peer
		 * consumes the packet before the top of the loop comes again. */
		next = skb->next;
		is_keepalive = skb->len == message_data_len(0);
		if (likely(!socket_send_skb_to_peer(peer, skb, 0 /* TODO: Should we copy the DSCP value from the enclosed packet? */) && !is_keepalive))
			timers_data_sent(peer);
	}
}

static void message_create_data_done(struct sk_buff *skb, struct wireguard_peer *peer)
{
	struct packet_bundle *bundle = *((struct packet_bundle **)skb->cb);
	/* A packet completed successfully, so we deincrement the counter of packets
	 * remaining, and if we hit zero we can send it off. */
	if (atomic_dec_and_test(&bundle->count))
		send_off_bundle(bundle, peer);
	keep_key_fresh(peer);
}

int packet_send_queue(struct wireguard_peer *peer)
{
	struct packet_bundle *bundle;
	struct sk_buff_head local_queue;
	struct sk_buff *skb, *next, *first;
	unsigned long flags;
	bool parallel = true;

	/* Steal the current queue into our local one. */
	skb_queue_head_init(&local_queue);
	spin_lock_irqsave(&peer->tx_packet_queue.lock, flags);
	skb_queue_splice_init(&peer->tx_packet_queue, &local_queue);
	spin_unlock_irqrestore(&peer->tx_packet_queue.lock, flags);

	first = skb_peek(&local_queue);
	if (unlikely(!first))
		goto out;

	/* Remove the circularity from the queue, so that we can iterate on
	 * on the skbs themselves. */
	local_queue.prev->next = local_queue.next->prev = NULL;

	/* The first pointer of the control block is a pointer to the bundle
	 * and after that, in the first packet only, is where we actually store
	 * the bundle data. This saves us a call to kmalloc. */
	bundle = (struct packet_bundle *)(first->cb + sizeof(void *));
	atomic_set(&bundle->count, skb_queue_len(&local_queue));
	bundle->first = first;

	/* Non-parallel path for the case of only one packet that's small */
	if (skb_queue_len(&local_queue) == 1 && first->len <= 256)
		parallel = false;

	for (skb = first; skb; skb = next) {
		/* We store the next pointer locally because we might free skb
		 * before the top of the loop comes again. */
		next = skb->next;

		/* We set the first pointer in cb to point to the bundle data. */
		*(struct packet_bundle **)skb->cb = bundle;

		/* We submit it for encryption and sending. */
		switch (packet_create_data(skb, peer, message_create_data_done, parallel)) {
		case 0:
			/* If all goes well, we can simply deincrement the queue counter. Even
			 * though skb_dequeue() would do this for us, we don't want to break the
			 * links between packets, so we just traverse the list normally and
			 * deincrement the counter manually each time a packet is consumed. */
			--local_queue.qlen;
			break;
		case -ENOKEY:
			/* ENOKEY means that we don't have a valid session for the peer, which
			 * means we should initiate a session, and then requeue everything. */
			ratelimit_packet_send_handshake_initiation(peer);
			/* Fall through */
		case -EBUSY:
			/* EBUSY happens when the parallel workers are all filled up, in which
			 * case we should requeue everything. */
			if (skb->prev) {
				/* Since we're requeuing skb and everything after skb, we make
				 * sure that the previously successfully sent packets don't link
				 * to the requeued packets, which will be sent independently the
				 * next time this function is called. */
				skb->prev->next = NULL;
				skb->prev = NULL;
			}
			if (atomic_sub_and_test(local_queue.qlen, &bundle->count)) {
				/* We remove the requeued packets from the count of total packets
				 * that were successfully submitted, which means we then must see
				 * if we were the ones to get it to zero. If we are at zero, we
				 * only send the previous successful packets if there actually were
				 * packets that succeeded before skb. */
				if (skb != first)
					send_off_bundle(bundle, peer);
			}
			/* We stick the remaining skbs from local_queue at the top of the peer's
			 * queue again, setting the top of local_queue to be the skb that begins
			 * the requeueing. */
			local_queue.next = skb;
			spin_lock_irqsave(&peer->tx_packet_queue.lock, flags);
			skb_queue_splice(&local_queue, &peer->tx_packet_queue);
			spin_unlock_irqrestore(&peer->tx_packet_queue.lock, flags);
			goto out;
		default:
			/* If we failed for any other reason, we want to just free the packet and
			 * forget about it, so we first deincrement the queue counter as in the
			 * successful case above. */
			--local_queue.qlen;
			if (skb == first && next) {
				/* If it's the first one that failed, we need to move the bundle data
				 * to the next packet. Then, all subsequent assignments of the bundle
				 * pointer will be to the moved data. */
				*(struct packet_bundle *)(next->cb + sizeof(void *)) = *bundle;
				bundle = (struct packet_bundle *)(next->cb + sizeof(void *));
				bundle->first = next;
			}
			/* We remove the skb from the list and free it. */
			if (skb->prev)
				skb->prev->next = skb->next;
			if (skb->next)
				skb->next->prev = skb->prev;
			kfree_skb(skb);
			if (atomic_dec_and_test(&bundle->count)) {
				/* As above, if this failed packet pushes the count to zero, we have to
				 * be the ones to send it off only in the case that there's something to
				 * send. */
				if (skb != first)
					send_off_bundle(bundle, peer);
			}
			/* Only at the bottom do we update our local `first` variable, because we need it
			 * in the check above. But it's important that bundle->first is updated earlier when
			 * actually moving the bundle. */
			first = bundle->first;
		}
	}
out:
	return NETDEV_TX_OK;
}
