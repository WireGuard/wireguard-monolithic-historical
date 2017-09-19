/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef QUEUEING_H
#define QUEUEING_H

#include "peer.h"
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct wireguard_device;
struct wireguard_peer;
struct multicore_worker;
struct crypt_queue;
struct sk_buff;

/* queueing.c APIs: */
extern struct kmem_cache *crypt_ctx_cache __read_mostly;
int init_crypt_ctx_cache(void);
void deinit_crypt_ctx_cache(void);
int packet_queue_init(struct crypt_queue *queue, work_func_t function, bool multicore);
struct multicore_worker __percpu *packet_alloc_percpu_multicore_worker(work_func_t function, void *ptr);

/* receive.c APIs: */
void packet_receive(struct wireguard_device *wg, struct sk_buff *skb);
void packet_handshake_receive_worker(struct work_struct *work);
/* Workqueue workers: */
void packet_rx_worker(struct work_struct *work);
void packet_decrypt_worker(struct work_struct *work);

/* send.c APIs: */
void packet_send_queued_handshake_initiation(struct wireguard_peer *peer, bool is_retry);
void packet_send_handshake_response(struct wireguard_peer *peer);
void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index);
void packet_send_keepalive(struct wireguard_peer *peer);
void packet_send_staged_packets(struct wireguard_peer *peer);
/* Workqueue workers: */
void packet_handshake_send_worker(struct work_struct *work);
void packet_tx_worker(struct work_struct *work);
void packet_encrypt_worker(struct work_struct *work);

struct packet_cb {
	u64 nonce;
	u8 ds;
};
#define PACKET_CB(skb) ((struct packet_cb *)skb->cb)

struct crypt_ctx {
	struct list_head per_peer_node, per_device_node;
	union {
		struct sk_buff_head packets;
		struct sk_buff *skb;
	};
	atomic_t is_finished;
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
	struct endpoint endpoint;
};

/* Returns either the correct skb->protocol value, or 0 if invalid. */
static inline __be16 skb_examine_untrusted_ip_hdr(struct sk_buff *skb)
{
	if (skb_network_header(skb) >= skb->head && (skb_network_header(skb) + sizeof(struct iphdr)) <= skb_tail_pointer(skb) && ip_hdr(skb)->version == 4)
		return htons(ETH_P_IP);
	if (skb_network_header(skb) >= skb->head && (skb_network_header(skb) + sizeof(struct ipv6hdr)) <= skb_tail_pointer(skb) && ipv6_hdr(skb)->version == 6)
		return htons(ETH_P_IPV6);
	return 0;
}

static inline unsigned int skb_padding(struct sk_buff *skb)
{
	/* We do this modulo business with the MTU, just in case the networking layer
	 * gives us a packet that's bigger than the MTU. Now that we support GSO, this
	 * shouldn't be a real problem, and this can likely be removed. But, caution! */
	unsigned int last_unit = skb->len % skb->dev->mtu;
	unsigned int padded_size = (last_unit + MESSAGE_PADDING_MULTIPLE - 1) & ~(MESSAGE_PADDING_MULTIPLE - 1);
	if (padded_size > skb->dev->mtu)
		padded_size = skb->dev->mtu;
	return padded_size - last_unit;
}

static inline void skb_reset(struct sk_buff *skb)
{
	skb_scrub_packet(skb, false);
	memset(&skb->headers_start, 0, offsetof(struct sk_buff, headers_end) - offsetof(struct sk_buff, headers_start));
	skb->queue_mapping = 0;
	skb->nohdr = 0;
	skb->peeked = 0;
	skb->mac_len = 0;
	skb->dev = NULL;
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
	skb_reset_tc(skb);
#endif
	skb->hdr_len = skb_headroom(skb);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);
	skb_reset_inner_headers(skb);
}

static inline int choose_cpu(int *stored_cpu, unsigned int id)
{
	unsigned int cpu = *stored_cpu, cpu_index, i;
	if (unlikely(cpu == nr_cpumask_bits || !cpumask_test_cpu(cpu, cpu_online_mask))) {
		cpu_index = id % cpumask_weight(cpu_online_mask);
		cpu = cpumask_first(cpu_online_mask);
		for (i = 0; i < cpu_index; ++i)
			cpu = cpumask_next(cpu, cpu_online_mask);
		*stored_cpu = cpu;
	}
	return cpu;
}

/* This function is racy, in the sense that next is unlocked, so it could return
 * the same CPU twice. A race-free version of this would be to instead store an
 * atomic sequence number, do an increment-and-return, and then iterate through
 * every possible CPU until we get to that index -- choose_cpu. However that's
 * a bit slower, and it doesn't seem like this potential race actually introduces
 * any performance loss, so we live with it. */
static inline int cpumask_next_online(int *next)
{
	int cpu = *next;
	while (unlikely(!cpumask_test_cpu(cpu, cpu_online_mask)))
		cpu = cpumask_next(cpu, cpu_online_mask) % nr_cpumask_bits;
	*next = cpumask_next(cpu, cpu_online_mask) % nr_cpumask_bits;
	return cpu;
}

static inline struct list_head *queue_dequeue(struct crypt_queue *queue)
{
	struct list_head *node;
	spin_lock_bh(&queue->lock);
	node = queue->queue.next;
	if (&queue->queue == node) {
		spin_unlock_bh(&queue->lock);
		return NULL;
	}
	list_del(node);
	--queue->len;
	spin_unlock_bh(&queue->lock);
	return node;
}

static inline bool queue_enqueue(struct crypt_queue *queue, struct list_head *node, int limit)
{
	spin_lock_bh(&queue->lock);
	if (limit && queue->len >= limit) {
		spin_unlock_bh(&queue->lock);
		return false;
	}
	list_add_tail(node, &queue->queue);
	++queue->len;
	spin_unlock_bh(&queue->lock);
	return true;
}

static inline struct crypt_ctx *queue_dequeue_per_peer(struct crypt_queue *queue)
{
	struct list_head *node = queue_dequeue(queue);
	return node ? list_entry(node, struct crypt_ctx, per_peer_node) : NULL;
}

static inline struct crypt_ctx *queue_dequeue_per_device(struct crypt_queue *queue)
{
	struct list_head *node = queue_dequeue(queue);
	return node ? list_entry(node, struct crypt_ctx, per_device_node) : NULL;
}

static inline struct crypt_ctx *queue_first_per_peer(struct crypt_queue *queue)
{
	return list_first_entry_or_null(&queue->queue, struct crypt_ctx, per_peer_node);
}

static inline bool queue_enqueue_per_peer(struct crypt_queue *peer_queue, struct crypt_ctx *ctx)
{
	return queue_enqueue(peer_queue, &ctx->per_peer_node, MAX_QUEUED_PACKETS);
}

static inline bool queue_enqueue_per_device_and_peer(struct crypt_queue *device_queue, struct crypt_queue *peer_queue, struct crypt_ctx *ctx, struct workqueue_struct *wq, int *next_cpu)
{
	int cpu;
	if (unlikely(!queue_enqueue_per_peer(peer_queue, ctx)))
		return false;
	cpu = cpumask_next_online(next_cpu);
	queue_enqueue(device_queue, &ctx->per_device_node, 0);
	queue_work_on(cpu, wq, &per_cpu_ptr(device_queue->worker, cpu)->work);
	return true;
}

#ifdef DEBUG
bool packet_counter_selftest(void);
#endif

#endif
