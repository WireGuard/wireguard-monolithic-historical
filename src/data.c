/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "noise.h"
#include "device.h"
#include "peer.h"
#include "messages.h"
#include "packets.h"
#include "timers.h"
#include "hashtables.h"

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <net/ip_tunnels.h>
#include <net/xfrm.h>
#include <crypto/algapi.h>

struct crypt_ctx {
	struct list_head per_peer_head;
	struct list_head per_device_head;
	union {
		struct sk_buff_head packets;
		struct sk_buff *skb;
	};
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
	struct endpoint endpoint;
	atomic_t is_finished;
};

/**
 * queue_dequeue - Atomically remove the first item in a queue.
 *
 * @return The address of the dequeued item, or NULL if the queue is empty.
 *
 * This function is safe to execute concurrently with any number of
 * queue_enqueue() calls, but *not* with another queue_dequeue() call
 * operating on the same queue.
 */
static struct list_head *queue_dequeue(struct crypt_queue *queue)
{
	struct list_head *first, *second;
	first = READ_ONCE(queue->list.next);
	if (first == &queue->list)
		return NULL;
	do {
		second = READ_ONCE(first->next);
		WRITE_ONCE(queue->list.next, second);
	} while (cmpxchg(&second->prev, first, &queue->list) != first);
	if (first)
		atomic_dec(&queue->qlen);
	return first;
}

/**
 * queue_enqueue - Atomically append an item to the tail of a queue.
 *
 * This function is safe to execute concurrently with any number of other
 * queue_enqueue() calls, as well as with one queue_dequeue() call
 * operating on the same queue.
 */
static bool queue_enqueue(struct crypt_queue *queue, struct list_head *head, int limit)
{
	bool have_space = !limit || atomic_inc_return(&queue->qlen) <= limit;
	if (have_space) {
		struct list_head *last;
		WRITE_ONCE(head->next, &queue->list);
		do {
			last = READ_ONCE(queue->list.prev);
			WRITE_ONCE(head->prev, last);
		} while (cmpxchg(&queue->list.prev, last, head) != last);
		WRITE_ONCE(last->next, head);
	} else
		atomic_dec(&queue->qlen);
	return have_space;
}

static inline struct crypt_ctx *queue_dequeue_per_peer(struct crypt_queue *queue)
{
	struct list_head *head = queue_dequeue(queue);
	return head ? list_entry(head, struct crypt_ctx, per_peer_head) : NULL;
}

static inline struct crypt_ctx *queue_dequeue_per_device(struct crypt_queue *queue)
{
	struct list_head *head = queue_dequeue(queue);
	return head ? list_entry(head, struct crypt_ctx, per_device_head) : NULL;
}

static inline bool queue_enqueue_per_peer(struct crypt_queue *queue, struct crypt_ctx *ctx)
{
	/* TODO: While using MAX_QUEUED_PACKETS makes sense for the init_queue, it's
	 * not ideal to be using this for the encrypt/decrypt queues or the send/receive
	 * queues, where dynamic_queue_limit (dql) should be used instead. */
	return queue_enqueue(queue, &(ctx)->per_peer_head, MAX_QUEUED_PACKETS);
}

static inline void queue_enqueue_per_device(struct crypt_queue __percpu *queue, struct crypt_ctx *ctx, struct workqueue_struct *wq, int *next_cpu)
{
	struct crypt_queue *cpu_queue;
	int cpu = cpumask_next_online(next_cpu);
	/* Avoid running parallel work on the same CPU as the one handling all
	 * of the serial work. This improves overall throughput and especially
	 * throughput stability where we have at least two cores left for
	 * parallel work. */
	if (cpu == ctx->peer->serial_work_cpu && num_online_cpus() >= 3)
		cpu = cpumask_next_online(next_cpu);
	cpu_queue = per_cpu_ptr(queue, cpu);
	queue_enqueue(cpu_queue, &ctx->per_device_head, 0);
	queue_work_on(cpu, wq, &cpu_queue->work);
}

static inline struct crypt_ctx *queue_first_per_peer(struct crypt_queue *queue)
{
	return list_first_entry_or_null(&(queue)->list, struct crypt_ctx, per_peer_head);
}

/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
static inline bool counter_validate(union noise_counter *counter, u64 their_counter)
{
	bool ret = false;
	unsigned long index, index_current, top, i;
	spin_lock_bh(&counter->receive.lock);

	if (unlikely(counter->receive.counter >= REJECT_AFTER_MESSAGES + 1 || their_counter >= REJECT_AFTER_MESSAGES))
		goto out;

	++their_counter;

	if (unlikely((COUNTER_WINDOW_SIZE + their_counter) < counter->receive.counter))
		goto out;

	index = their_counter >> ilog2(BITS_PER_LONG);

	if (likely(their_counter > counter->receive.counter)) {
		index_current = counter->receive.counter >> ilog2(BITS_PER_LONG);
		top = min_t(unsigned long, index - index_current, COUNTER_BITS_TOTAL / BITS_PER_LONG);
		for (i = 1; i <= top; ++i)
			counter->receive.backtrack[(i + index_current) & ((COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1)] = 0;
		counter->receive.counter = their_counter;
	}

	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;
	ret = !test_and_set_bit(their_counter & (BITS_PER_LONG - 1), &counter->receive.backtrack[index]);

out:
	spin_unlock_bh(&counter->receive.lock);
	return ret;
}
#include "selftest/counter.h"

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

static inline bool skb_encrypt(struct sk_buff *skb, struct noise_keypair *keypair, bool have_simd)
{
	struct scatterlist sg[MAX_SKB_FRAGS * 2 + 1];
	struct message_data *header;
	unsigned int padding_len, plaintext_len, trailer_len;
	int num_frags;
	struct sk_buff *trailer;

	/* Store the ds bit in the cb */
	PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0 /* No outer TOS: no leak. TODO: should we use flowi->tos as outer? */, ip_hdr(skb), skb);

	/* Calculate lengths */
	padding_len = skb_padding(skb);
	trailer_len = padding_len + noise_encrypted_len(0);
	plaintext_len = skb->len + padding_len;

	/* Expand data section to have room for padding and auth tag */
	num_frags = skb_cow_data(skb, trailer_len, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	/* Set the padding to zeros, and make sure it and the auth tag are part of the skb */
	memset(skb_tail_pointer(trailer), 0, padding_len);

	/* Expand head section to have room for our header and the network stack's headers. */
	if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM) < 0))
		return false;

	/* We have to remember to add the checksum to the innerpacket, in case the receiver forwards it. */
	if (likely(!skb_checksum_setup(skb, true)))
		skb_checksum_help(skb);

	/* Only after checksumming can we safely add on the padding at the end and the header. */
	header = (struct message_data *)skb_push(skb, sizeof(struct message_data));
	header->header.type = cpu_to_le32(MESSAGE_DATA);
	header->key_idx = keypair->remote_index;
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
	pskb_put(skb, trailer, trailer_len);

	/* Now we can encrypt the scattergather segments */
	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, sizeof(struct message_data), noise_encrypted_len(plaintext_len)) <= 0)
		return false;
	return chacha20poly1305_encrypt_sg(sg, sg, plaintext_len, NULL, 0, PACKET_CB(skb)->nonce, keypair->sending.key, have_simd);
}

static inline bool skb_decrypt(struct sk_buff *skb, struct noise_symmetric_key *key)
{
	struct scatterlist sg[MAX_SKB_FRAGS * 2 + 1];
	struct sk_buff *trailer;
	int num_frags;

	if (unlikely(!key))
		return false;

	if (unlikely(!key->is_valid || time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME) || key->counter.receive.counter >= REJECT_AFTER_MESSAGES)) {
		key->is_valid = false;
		return false;
	}

	PACKET_CB(skb)->nonce = le64_to_cpu(((struct message_data *)skb->data)->counter);
	skb_pull(skb, sizeof(struct message_data));
	num_frags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0)
		return false;

	if (!chacha20poly1305_decrypt_sg(sg, sg, skb->len, NULL, 0, PACKET_CB(skb)->nonce, key->key))
		return false;

	return !pskb_trim(skb, skb->len - noise_encrypted_len(0));
}

static struct kmem_cache *crypt_ctx_cache __read_mostly;

int __init init_crypt_ctx_cache(void)
{
	crypt_ctx_cache = KMEM_CACHE(crypt_ctx, 0);
	if (!crypt_ctx_cache)
		return -ENOMEM;
	return 0;
}

void deinit_crypt_ctx_cache(void)
{
	kmem_cache_destroy(crypt_ctx_cache);
}

static void free_ctx(struct crypt_ctx *ctx)
{
	if (ctx->keypair)
		noise_keypair_put(ctx->keypair);
	peer_put(ctx->peer);
	skb_queue_purge(&ctx->packets);
	kmem_cache_free(crypt_ctx_cache, ctx);
}

static bool populate_sending_ctx(struct crypt_ctx *ctx)
{
	struct noise_symmetric_key *key;
	struct sk_buff *skb;

	rcu_read_lock_bh();
	ctx->keypair = noise_keypair_get(rcu_dereference_bh(ctx->peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	if (unlikely(!ctx->keypair))
		return false;
	key = &ctx->keypair->sending;
	if (unlikely(!key || !key->is_valid))
		goto out_nokey;
	if (unlikely(time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME)))
		goto out_invalid;

	skb_queue_walk(&ctx->packets, skb) {
		PACKET_CB(skb)->nonce = atomic64_inc_return(&key->counter.counter) - 1;
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
	}

	return true;

out_invalid:
	key->is_valid = false;
out_nokey:
	noise_keypair_put(ctx->keypair);
	ctx->keypair = NULL;
	return false;
}

void packet_send_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct crypt_ctx *ctx;

	while ((ctx = queue_first_per_peer(queue)) != NULL && atomic_read(&ctx->is_finished)) {
		queue_dequeue(queue);
		packet_create_data_done(&ctx->packets, ctx->peer);
		peer_put(ctx->peer);
		kmem_cache_free(crypt_ctx_cache, ctx);
	}
}

void packet_encrypt_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct sk_buff *skb, *tmp;
	struct wireguard_peer *peer;
	bool have_simd = chacha20poly1305_init_simd();

	while ((ctx = queue_dequeue_per_device(queue)) != NULL) {
		skb_queue_walk_safe(&ctx->packets, skb, tmp) {
			if (likely(skb_encrypt(skb, ctx->keypair, have_simd))) {
				skb_reset(skb);
			} else {
				__skb_unlink(skb, &ctx->packets);
				dev_kfree_skb(skb);
			}
		}
		/* Dereferencing ctx is unsafe once ctx->is_finished == true, so
		 * we grab an additional reference to peer. */
		peer = peer_rcu_get(ctx->peer);
		atomic_set(&ctx->is_finished, true);
		queue_work_on(choose_cpu(&peer->serial_work_cpu, peer->internal_id), peer->device->packet_crypt_wq, &peer->send_queue.work);
		peer_put(peer);
	}
	chacha20poly1305_deinit_simd(have_simd);
}

void packet_init_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct wireguard_peer *peer = container_of(queue, struct wireguard_peer, init_queue);
	struct wireguard_device *wg = peer->device;

	spin_lock(&peer->init_queue_lock);
	while ((ctx = queue_first_per_peer(queue)) != NULL) {
		if (unlikely(!populate_sending_ctx(ctx))) {
			packet_queue_handshake_initiation(peer, false);
			break;
		}
		queue_dequeue(queue);
		if (likely(queue_enqueue_per_peer(&peer->send_queue, ctx)))
			queue_enqueue_per_device(wg->send_queue, ctx, wg->packet_crypt_wq, &wg->encrypt_cpu);
		else
			free_ctx(ctx);
	}
	spin_unlock(&peer->init_queue_lock);
}

void packet_create_data(struct wireguard_peer *peer, struct sk_buff_head *packets)
{
	struct crypt_ctx *ctx;
	struct sk_buff *skb;
	struct wireguard_device *wg = peer->device;
	bool need_handshake = false;

	ctx = kmem_cache_zalloc(crypt_ctx_cache, GFP_ATOMIC);
	if (unlikely(!ctx)) {
		skb_queue_purge(packets);
		return;
	}
	skb_queue_head_init(&ctx->packets);
	skb_queue_splice_tail(packets, &ctx->packets);
	ctx->peer = peer_rcu_get(peer);

	/* If there are already packets on the init queue, these must go behind
	 * them to maintain the correct order, so we can only take the fast path
	 * when the init queue is empty. */
	if (likely(list_empty(&peer->init_queue.list))) {
		if (likely(populate_sending_ctx(ctx))) {
			if (likely(queue_enqueue_per_peer(&peer->send_queue, ctx)))
				queue_enqueue_per_device(wg->send_queue, ctx, wg->packet_crypt_wq, &wg->encrypt_cpu);
			else
				free_ctx(ctx);
			return;
		}
		/* Initialization failed, so we need a new keypair. */
		need_handshake = true;
	}

	/* We orphan the packets if we're waiting on a handshake, so that they
	 * don't block a socket's pool. */
	skb_queue_walk(&ctx->packets, skb)
		skb_orphan(skb);

	/* Packets are kept around in the init queue as long as there is an
	 * ongoing handshake. Throw out the oldest packets instead of the new
	 * ones. If we cannot acquire the lock, packets are being dequeued on
	 * another thread, so race for the open slot. */
	while (unlikely(!queue_enqueue_per_peer(&peer->init_queue, ctx))) {
		if (spin_trylock(&peer->init_queue_lock)) {
			struct crypt_ctx *tmp = queue_dequeue_per_peer(&peer->init_queue);
			if (likely(tmp))
				free_ctx(tmp);
			spin_unlock(&peer->init_queue_lock);
		}
	}
	/* Oops, we added something to the queue while removing the peer. */
	if (unlikely(atomic_read(&peer->is_draining))) {
		packet_purge_init_queue(peer);
		return;
	}
	if (need_handshake)
		packet_queue_handshake_initiation(peer, false);
	/* If we have a valid keypair, but took the slow path because init_queue
	 * had packets on it, init_queue.worker() may have finished
	 * processing the existing packets and returned since we checked if the
	 * init_queue was empty. Run the worker again if this is the only ctx
	 * remaining on the queue. */
	if (unlikely(queue_first_per_peer(&peer->init_queue) == ctx))
		queue_work(peer->device->packet_crypt_wq, &peer->init_queue.work);
}

void packet_receive_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct sk_buff *skb;

	local_bh_disable();
	while ((ctx = queue_first_per_peer(queue)) != NULL && atomic_read(&ctx->is_finished)) {
		queue_dequeue(queue);
		if (likely((skb = ctx->skb) != NULL)) {
			if (likely(counter_validate(&ctx->keypair->receiving.counter, PACKET_CB(skb)->nonce))) {
				skb_reset(skb);
				packet_consume_data_done(skb, ctx->peer, &ctx->endpoint, noise_received_with_keypair(&ctx->peer->keypairs, ctx->keypair));
			}
			else {
				net_dbg_ratelimited("%s: Packet has invalid nonce %Lu (max %Lu)\n", ctx->peer->device->dev->name, PACKET_CB(ctx->skb)->nonce, ctx->keypair->receiving.counter.receive.counter);
				dev_kfree_skb(skb);
			}
		}
		noise_keypair_put(ctx->keypair);
		peer_put(ctx->peer);
		kmem_cache_free(crypt_ctx_cache, ctx);
	}
	local_bh_enable();
}

void packet_decrypt_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct wireguard_peer *peer;

	while ((ctx = queue_dequeue_per_device(queue)) != NULL) {
		if (unlikely(socket_endpoint_from_skb(&ctx->endpoint, ctx->skb) < 0 || !skb_decrypt(ctx->skb, &ctx->keypair->receiving))) {
			dev_kfree_skb(ctx->skb);
			ctx->skb = NULL;
		}
		/* Dereferencing ctx is unsafe once ctx->is_finished == true, so
		 * we take a reference here first. */
		peer = peer_rcu_get(ctx->peer);
		atomic_set(&ctx->is_finished, true);
		queue_work_on(choose_cpu(&peer->serial_work_cpu, peer->internal_id), peer->device->packet_crypt_wq, &peer->receive_queue.work);
		peer_put(peer);
	}
}

void packet_consume_data(struct sk_buff *skb, struct wireguard_device *wg)
{
	struct crypt_ctx *ctx;
	struct noise_keypair *keypair;
	__le32 idx = ((struct message_data *)skb->data)->key_idx;

	rcu_read_lock_bh();
	keypair = noise_keypair_get((struct noise_keypair *)index_hashtable_lookup(&wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx));
	rcu_read_unlock_bh();
	if (unlikely(!keypair)) {
		dev_kfree_skb(skb);
		return;
	}

	ctx = kmem_cache_zalloc(crypt_ctx_cache, GFP_ATOMIC);
	if (unlikely(!ctx)) {
		peer_put(ctx->keypair->entry.peer);
		noise_keypair_put(keypair);
		dev_kfree_skb(skb);
		return;
	}
	ctx->keypair = keypair;
	ctx->skb = skb;
	/* index_hashtable_lookup() already gets a reference to peer. */
	ctx->peer = ctx->keypair->entry.peer;

	if (likely(queue_enqueue_per_peer(&ctx->peer->receive_queue, ctx)))
		queue_enqueue_per_device(wg->receive_queue, ctx, wg->packet_crypt_wq, &wg->decrypt_cpu);
	else {
		/* TODO: replace this with a call to free_ctx when receiving uses skb_queues as well. */
		noise_keypair_put(ctx->keypair);
		peer_put(ctx->peer);
		dev_kfree_skb(ctx->skb);
		kmem_cache_free(crypt_ctx_cache, ctx);
	}
}

void packet_purge_init_queue(struct wireguard_peer *peer)
{
	struct crypt_ctx *ctx;
	spin_lock(&peer->init_queue_lock);
	while ((ctx = queue_dequeue_per_peer(&peer->init_queue)) != NULL)
		free_ctx(ctx);
	spin_unlock(&peer->init_queue_lock);
}
