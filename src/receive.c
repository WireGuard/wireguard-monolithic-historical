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
	struct pcpu_sw_netstats *tstats = get_cpu_ptr(peer->device->dev->tstats);
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

static inline int skb_prepare_header(struct sk_buff *skb, struct wireguard_device *wg)
{
	struct udphdr *udp;
	size_t data_offset, data_len;
	enum message_type message_type;
	if (unlikely(skb_examine_untrusted_ip_hdr(skb) != skb->protocol || skb_transport_header(skb) < skb->head || (skb_transport_header(skb) + sizeof(struct udphdr)) > skb_tail_pointer(skb)))
		return -EINVAL; /* Bogus IP header */
	udp = udp_hdr(skb);
	data_offset = (u8 *)udp - skb->data;
	if (unlikely(data_offset > U16_MAX || data_offset + sizeof(struct udphdr) > skb->len))
		return -EINVAL;  /* Packet has offset at impossible location or isn't big enough to have UDP fields*/
	data_len = ntohs(udp->len);
	if (unlikely(data_len < sizeof(struct udphdr) || data_len > skb->len - data_offset))
		return -EINVAL;  /* UDP packet is reporting too small of a size or lying about its size */
	data_len -= sizeof(struct udphdr);
	data_offset = (u8 *)udp + sizeof(struct udphdr) - skb->data;
	if (unlikely(!pskb_may_pull(skb, data_offset + sizeof(struct message_header)) || pskb_trim(skb, data_len + data_offset) < 0))
		return -EINVAL;
	skb_pull(skb, data_offset);
	if (unlikely(skb->len != data_len))
		return -EINVAL; /* Final len does not agree with calculated len */
	message_type = message_determine_type(skb);
	__skb_push(skb, data_offset);
	if (unlikely(!pskb_may_pull(skb, data_offset + message_header_sizes[message_type])))
		return -EINVAL;
	__skb_pull(skb, data_offset);
	return message_type;
}

static void receive_handshake_packet(struct wireguard_device *wg, struct sk_buff *skb)
{
	static unsigned long last_under_load = 0; /* Yes this is global, so that our load calculation applies to the whole system. */
	struct wireguard_peer *peer = NULL;
	enum message_type message_type;
	bool under_load;
	enum cookie_mac_state mac_state;
	bool packet_needs_cookie;

	message_type = message_determine_type(skb);

	if (message_type == MESSAGE_HANDSHAKE_COOKIE) {
		net_dbg_skb_ratelimited("%s: Receiving cookie response from %pISpfsc\n", wg->dev->name, skb);
		cookie_message_consume((struct message_handshake_cookie *)skb->data, wg);
		return;
	}

	under_load = skb_queue_len(&wg->incoming_handshakes) >= MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	if (under_load)
		last_under_load = jiffies;
	else
		under_load = time_is_after_jiffies(last_under_load + HZ);
	mac_state = cookie_validate_packet(&wg->cookie_checker, skb, under_load);
	if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) || (!under_load && mac_state == VALID_MAC_BUT_NO_COOKIE))
		packet_needs_cookie = false;
	else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE)
		packet_needs_cookie = true;
	else {
		net_dbg_skb_ratelimited("%s: Invalid MAC of handshake, dropping packet from %pISpfsc\n", wg->dev->name, skb);
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
			net_dbg_skb_ratelimited("%s: Invalid handshake initiation from %pISpfsc\n", wg->dev->name, skb);
			return;
		}
		update_latest_addr(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake initiation from peer %Lu (%pISpfsc)\n", wg->dev->name, peer->internal_id, &peer->endpoint.addr);
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
			net_dbg_skb_ratelimited("%s: Invalid handshake response from %pISpfsc\n", wg->dev->name, skb);
			return;
		}
		update_latest_addr(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake response from peer %Lu (%pISpfsc)\n", wg->dev->name, peer->internal_id, &peer->endpoint.addr);
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
		cond_resched();
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
		packet_queue_handshake_initiation(peer, false);
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
	dev = wg->dev;

	if (unlikely(used_new_key)) {
		peer->sent_lastminute_handshake = false;
		packet_send_queue(peer);
		timers_handshake_complete(peer);
	}

	keep_key_fresh(peer);

	/* A packet with length 0 is a keepalive packet */
	if (unlikely(!skb->len)) {
		net_dbg_ratelimited("%s: Receiving keepalive packet from peer %Lu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
		goto packet_processed;
	}

	if (unlikely(skb_network_header(skb) < skb->head))
		goto dishonest_packet_size;
	if (unlikely(!(pskb_network_may_pull(skb, sizeof(struct iphdr)) && (ip_hdr(skb)->version == 4 || (ip_hdr(skb)->version == 6 && pskb_network_may_pull(skb, sizeof(struct ipv6hdr)))))))
		goto dishonest_packet_type;

	skb->dev = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = skb_examine_untrusted_ip_hdr(skb);
	if (skb->protocol == htons(ETH_P_IP)) {
		len = ntohs(ip_hdr(skb)->tot_len);
		if (unlikely(len < sizeof(struct iphdr)))
			goto dishonest_packet_size;
		if (INET_ECN_is_ce(PACKET_CB(skb)->ds))
			IP_ECN_set_ce(ip_hdr(skb));

	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		len = ntohs(ipv6_hdr(skb)->payload_len) + sizeof(struct ipv6hdr);
		if (INET_ECN_is_ce(PACKET_CB(skb)->ds))
			IP6_ECN_set_ce(skb, ipv6_hdr(skb));
	} else
		goto dishonest_packet_type;

	if (unlikely(len > skb->len)) {
		goto dishonest_packet_size;
	}
	if (len < skb->len && unlikely(pskb_trim(skb, len)))
		goto packet_processed;

	timers_data_received(peer);

	routed_peer = routing_table_lookup_src(&wg->peer_routing_table, skb);
	peer_put(routed_peer); /* We don't need the extra reference. */

	if (unlikely(routed_peer != peer))
		goto dishonest_packet_peer;

	len = skb->len;
	if (likely(netif_rx(skb) == NET_RX_SUCCESS))
		rx_stats(peer, len);
	else {
		++dev->stats.rx_dropped;
		net_dbg_ratelimited("%s: Failed to give packet to userspace from peer %Lu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	}
	goto continue_processing;

dishonest_packet_peer:
	net_dbg_skb_ratelimited("%s: Packet has unallowed src IP (%pISc) from peer %Lu (%pISpfsc)\n", peer->device->dev->name, skb, peer->internal_id, &peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_frame_errors;
	goto packet_processed;
dishonest_packet_type:
	net_dbg_ratelimited("%s: Packet is neither ipv4 nor ipv6 from peer %Lu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_frame_errors;
	goto packet_processed;
dishonest_packet_size:
	net_dbg_ratelimited("%s: Packet has incorrect size from peer %Lu (%pISpfsc)\n", peer->device->dev->name, peer->internal_id, &peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_length_errors;
	goto packet_processed;
packet_processed:
	dev_kfree_skb(skb);
continue_processing:
	timers_any_authenticated_packet_received(peer);
	timers_any_authenticated_packet_traversal(peer);
	peer_put(peer);
}

void packet_receive(struct wireguard_device *wg, struct sk_buff *skb)
{
	int message_type = skb_prepare_header(skb, wg);
	if (unlikely(message_type < 0))
		goto err;
	switch (message_type) {
	case MESSAGE_HANDSHAKE_INITIATION:
	case MESSAGE_HANDSHAKE_RESPONSE:
	case MESSAGE_HANDSHAKE_COOKIE: {
		int cpu_index, cpu, target_cpu;
		if (skb_queue_len(&wg->incoming_handshakes) > MAX_QUEUED_INCOMING_HANDSHAKES) {
			net_dbg_skb_ratelimited("%s: Too many handshakes queued, dropping packet from %pISpfsc\n", wg->dev->name, skb);
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
		net_dbg_skb_ratelimited("%s: Invalid packet from %pISpfsc\n", wg->dev->name, skb);
		goto err;
	}
	return;

err:
	dev_kfree_skb(skb);
}
