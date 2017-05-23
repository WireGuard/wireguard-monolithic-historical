/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "packets.h"
#include "device.h"
#include "peer.h"
#include "timers.h"
#include "messages.h"
#include "cookie.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/ip_tunnels.h>

static inline void rx_stats(struct wireguard_peer *peer, size_t len)
{
	struct pcpu_sw_netstats *tstats = get_cpu_ptr(netdev_pub(peer->device)->tstats);
	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_bytes += len;
	++tstats->rx_packets;
	u64_stats_update_end(&tstats->syncp);
	put_cpu_ptr(tstats);
	peer->rx_bytes += len;
}

static inline void update_latest_addr(struct wireguard_peer *peer, struct sk_buff *skb)
{
	struct endpoint endpoint;
	if (!socket_endpoint_from_skb(&endpoint, skb))
		socket_set_peer_endpoint(peer, &endpoint);
}

static inline int skb_prepare_header(struct sk_buff *skb)
{
	struct udphdr *udp;
	size_t data_offset, data_len;
	enum message_type message_type;

	if (unlikely(skb->len < sizeof(struct iphdr)))
		return -EINVAL;
	if (unlikely(ip_hdr(skb)->version != 4 && ip_hdr(skb)->version != 6))
		return -EINVAL;
	if (unlikely(ip_hdr(skb)->version == 6 && skb->len < sizeof(struct ipv6hdr)))
		return -EINVAL;

	udp = udp_hdr(skb);
	data_offset = (u8 *)udp - skb->data;
	if (unlikely(data_offset > U16_MAX)) {
		net_dbg_skb_ratelimited("Packet has offset at impossible location from %pISpfsc\n", skb);
		return -EINVAL;
	}
	if (unlikely(data_offset + sizeof(struct udphdr) > skb->len)) {
		net_dbg_skb_ratelimited("Packet isn't big enough to have UDP fields from %pISpfsc\n", skb);
		return -EINVAL;
	}
	data_len = ntohs(udp->len);
	if (unlikely(data_len < sizeof(struct udphdr))) {
		net_dbg_skb_ratelimited("UDP packet is reporting too small of a size from %pISpfsc\n", skb);
		return -EINVAL;
	}
	if (unlikely(data_len > skb->len - data_offset)) {
		net_dbg_skb_ratelimited("UDP packet is lying about its size from %pISpfsc\n", skb);
		return -EINVAL;
	}
	data_len -= sizeof(struct udphdr);
	data_offset = (u8 *)udp + sizeof(struct udphdr) - skb->data;
	if (unlikely(!pskb_may_pull(skb, data_offset + sizeof(struct message_header)))) {
		net_dbg_skb_ratelimited("Could not pull header into data section from %pISpfsc\n", skb);
		return -EINVAL;
	}
	if (pskb_trim(skb, data_len + data_offset) < 0) {
		net_dbg_skb_ratelimited("Could not trim packet from %pISpfsc\n", skb);
		return -EINVAL;
	}
	skb_pull(skb, data_offset);
	if (unlikely(skb->len != data_len)) {
		net_dbg_skb_ratelimited("Final len does not agree with calculated len from %pISpfsc\n", skb);
		return -EINVAL;
	}
	message_type = message_determine_type(skb);
	__skb_push(skb, data_offset);
	if (unlikely(!pskb_may_pull(skb, data_offset + message_header_sizes[message_type]))) {
		net_dbg_skb_ratelimited("Could not pull full header into data section from %pISpfsc\n", skb);
		return -EINVAL;
	}
	__skb_pull(skb, data_offset);
	return message_type;
}

static void receive_handshake_packet(struct wireguard_device *wg, struct sk_buff *skb)
{
	struct wireguard_peer *peer = NULL;
	enum message_type message_type;
	bool under_load;
	enum cookie_mac_state mac_state;
	bool packet_needs_cookie;

	message_type = message_determine_type(skb);

	if (message_type == MESSAGE_HANDSHAKE_COOKIE) {
		net_dbg_skb_ratelimited("Receiving cookie response from %pISpfsc\n", skb);
		cookie_message_consume((struct message_handshake_cookie *)skb->data, wg);
		return;
	}

	under_load = skb_queue_len(&wg->incoming_handshakes) >= MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	mac_state = cookie_validate_packet(&wg->cookie_checker, skb, under_load);
	if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) || (!under_load && mac_state == VALID_MAC_BUT_NO_COOKIE))
		packet_needs_cookie = false;
	else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE)
		packet_needs_cookie = true;
	else {
		net_dbg_skb_ratelimited("Invalid MAC of handshake, dropping packet from %pISpfsc\n", skb);
		return;
	}

	switch (message_type) {
	case MESSAGE_HANDSHAKE_INITIATION: {
		struct message_handshake_initiation *message = (struct message_handshake_initiation *)skb->data;
		if (packet_needs_cookie) {
			packet_send_handshake_cookie(wg, skb, message->sender_index);
			return;
		}
		peer = noise_handshake_consume_initiation(message, wg);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("Invalid handshake initiation from %pISpfsc\n", skb);
			return;
		}
		update_latest_addr(peer, skb);
		net_dbg_ratelimited("Receiving handshake initiation from peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
		packet_send_handshake_response(peer);
		break;
	}
	case MESSAGE_HANDSHAKE_RESPONSE: {
		struct message_handshake_response *message = (struct message_handshake_response *)skb->data;
		if (packet_needs_cookie) {
			packet_send_handshake_cookie(wg, skb, message->sender_index);
			return;
		}
		peer = noise_handshake_consume_response(message, wg);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("Invalid handshake response from %pISpfsc\n", skb);
			return;
		}
		update_latest_addr(peer, skb);
		net_dbg_ratelimited("Receiving handshake response from peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
		if (noise_handshake_begin_session(&peer->handshake, &peer->keypairs, true)) {
			timers_ephemeral_key_created(peer);
			timers_handshake_complete(peer);
			peer->sent_lastminute_handshake = false;
			/* Calling this function will either send any existing packets in the queue
			 * and not send a keepalive, which is the best case, Or, if there's nothing
			 * in the queue, it will send a keepalive, in order to give immediate
			 * confirmation of the session. */
			packet_send_keepalive(peer);
		}
		break;
	}
	default:
		WARN(1, "Somehow a wrong type of packet wound up in the handshake queue!\n");
		return;
	}

	BUG_ON(!peer);

	rx_stats(peer, skb->len);
	timers_any_authenticated_packet_received(peer);
	timers_any_authenticated_packet_traversal(peer);
	peer_put(peer);
}

void packet_process_queued_handshake_packets(struct work_struct *work)
{
	struct wireguard_device *wg = container_of(work, struct handshake_worker, work)->wg;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&wg->incoming_handshakes)) != NULL) {
		receive_handshake_packet(wg, skb);
		dev_kfree_skb(skb);
		if (need_resched())
			schedule();
	}
}

static void keep_key_fresh(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	bool send = false;
	if (peer->sent_lastminute_handshake)
		return;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	if (likely(keypair && keypair->sending.is_valid) && keypair->i_am_the_initiator &&
	    unlikely(time_is_before_eq_jiffies64(keypair->sending.birthdate + REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT)))
		send = true;
	rcu_read_unlock_bh();

	if (send) {
		peer->sent_lastminute_handshake = true;
		packet_queue_handshake_initiation(peer);
	}
}

void packet_consume_data_done(struct sk_buff *skb, struct wireguard_peer *peer, struct endpoint *endpoint, bool used_new_key)
{
	struct net_device *dev;
	struct wireguard_peer *routed_peer;
	struct wireguard_device *wg;
	unsigned int len;

	socket_set_peer_endpoint(peer, endpoint);

	wg = peer->device;
	dev = netdev_pub(wg);

	if (unlikely(used_new_key)) {
		peer->sent_lastminute_handshake = false;
		packet_send_queue(peer);
	}

	keep_key_fresh(peer);

	/* A packet with length 0 is a keepalive packet */
	if (unlikely(!skb->len)) {
		net_dbg_ratelimited("Receiving keepalive packet from peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
		goto packet_processed;
	}

	if (!pskb_may_pull(skb, 1 /* For checking the ip version below */)) {
		++dev->stats.rx_errors;
		++dev->stats.rx_length_errors;
		net_dbg_ratelimited("Packet missing IP version from peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
		goto packet_processed;
	}

	skb->dev = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	if (skb->len >= sizeof(struct iphdr) && ip_hdr(skb)->version == 4) {
		skb->protocol = htons(ETH_P_IP);
		if (INET_ECN_is_ce(PACKET_CB(skb)->ds))
			IP_ECN_set_ce(ip_hdr(skb));
	} else if (skb->len >= sizeof(struct ipv6hdr) && ip_hdr(skb)->version == 6) {
		skb->protocol = htons(ETH_P_IPV6);
		if (INET_ECN_is_ce(PACKET_CB(skb)->ds))
			IP6_ECN_set_ce(skb, ipv6_hdr(skb));
	} else {
		++dev->stats.rx_errors;
		++dev->stats.rx_length_errors;
		net_dbg_ratelimited("Packet neither ipv4 nor ipv6 from peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
		goto packet_processed;
	}

	timers_data_received(peer);

	routed_peer = routing_table_lookup_src(&wg->peer_routing_table, skb);
	peer_put(routed_peer); /* We don't need the extra reference. */

	if (unlikely(routed_peer != peer)) {
		++dev->stats.rx_errors;
		++dev->stats.rx_frame_errors;
		net_dbg_skb_ratelimited("Packet has unallowed src IP (%pISc) from peer %Lu (%pISpfsc)\n", skb, peer->internal_id, &peer->endpoint.addr);
		goto packet_processed;
	}

	len = skb->len;
	if (likely(netif_rx(skb) == NET_RX_SUCCESS))
		rx_stats(peer, len);
	else {
		++dev->stats.rx_dropped;
		net_dbg_ratelimited("Failed to give packet to userspace from peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
	}
	goto continue_processing;

packet_processed:
	dev_kfree_skb(skb);
continue_processing:
	timers_any_authenticated_packet_received(peer);
	timers_any_authenticated_packet_traversal(peer);
	peer_put(peer);
}

void packet_receive(struct wireguard_device *wg, struct sk_buff *skb)
{
	int message_type = skb_prepare_header(skb);
	if (unlikely(message_type < 0))
		goto err;
	switch (message_type) {
	case MESSAGE_HANDSHAKE_INITIATION:
	case MESSAGE_HANDSHAKE_RESPONSE:
	case MESSAGE_HANDSHAKE_COOKIE: {
		int cpu_index, cpu, target_cpu;
		if (skb_queue_len(&wg->incoming_handshakes) > MAX_QUEUED_INCOMING_HANDSHAKES) {
			net_dbg_skb_ratelimited("Too many handshakes queued, dropping packet from %pISpfsc\n", skb);
			goto err;
		}
		skb_queue_tail(&wg->incoming_handshakes, skb);
		/* Select the CPU in a round-robin */
		cpu_index = ((unsigned int)atomic_inc_return(&wg->incoming_handshake_seqnr)) % cpumask_weight(cpu_online_mask);
		target_cpu = cpumask_first(cpu_online_mask);
		for (cpu = 0; cpu < cpu_index; ++cpu)
			target_cpu = cpumask_next(target_cpu, cpu_online_mask);
		/* Queues up a call to packet_process_queued_handshake_packets(skb): */
		queue_work_on(target_cpu, wg->incoming_handshake_wq, &per_cpu_ptr(wg->incoming_handshakes_worker, target_cpu)->work);
		break;
	}
	case MESSAGE_DATA:
		PACKET_CB(skb)->ds = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		packet_consume_data(skb, wg);
		break;
	default:
		net_dbg_skb_ratelimited("Invalid packet from %pISpfsc\n", skb);
		goto err;
	}
	return;

err:
	dev_kfree_skb(skb);
}
