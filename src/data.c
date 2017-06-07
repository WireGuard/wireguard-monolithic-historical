/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "noise.h"
#include "device.h"
#include "peer.h"
#include "messages.h"
#include "packets.h"
#include "queue.h"
#include "timers.h"
#include "hashtables.h"

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <net/ip_tunnels.h>
#include <net/xfrm.h>
#include <crypto/algapi.h>

static struct kmem_cache *crypt_ctx_cache __read_mostly;

int __init init_crypt_cache(void)
{
	crypt_ctx_cache = KMEM_CACHE(crypt_ctx, 0);
	if (!crypt_ctx_cache)
		return -ENOMEM;
	return 0;
}

void deinit_crypt_cache(void)
{
	kmem_cache_destroy(crypt_ctx_cache);
}

static void drop_ctx(struct crypt_ctx *ctx, bool sending)
{
	if (ctx->keypair)
		noise_keypair_put(ctx->keypair);
	peer_put(ctx->peer);
	if (sending)
		skb_queue_purge(&ctx->packets);
	else
		dev_kfree_skb(ctx->skb);
	kmem_cache_free(crypt_ctx_cache, ctx);
}

#define drop_ctx_and_continue(ctx, sending) ({ \
	drop_ctx(ctx, sending); \
	continue; \
})

#define drop_ctx_and_return(ctx, sending) ({ \
	drop_ctx(ctx, sending); \
	return; \
})

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

static inline bool packet_initialize_ctx(struct crypt_ctx *ctx)
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
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct sk_buff *skb, *tmp;
	struct wireguard_peer *peer = container_of(queue, struct wireguard_peer, send_queue);
	bool data_sent = false;

	timers_any_authenticated_packet_traversal(peer);
	while ((ctx = queue_first_peer(queue)) != NULL && atomic_read(&ctx->state) == CTX_FINISHED) {
		queue_dequeue(queue);
		skb_queue_walk_safe(&ctx->packets, skb, tmp) {
			bool is_keepalive = skb->len == message_data_len(0);
			if (likely(!socket_send_skb_to_peer(peer, skb, PACKET_CB(skb)->ds) && !is_keepalive))
				data_sent = true;
		}
		noise_keypair_put(ctx->keypair);
		peer_put(ctx->peer);
		kmem_cache_free(crypt_ctx_cache, ctx);
	}
	if (likely(data_sent))
		timers_data_sent(peer);
	keep_key_fresh_send(peer);
}

void packet_encrypt_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct sk_buff *skb, *tmp;
	struct wireguard_peer *peer;
	bool have_simd = chacha20poly1305_init_simd();

	while ((ctx = queue_dequeue_shared(queue)) != NULL) {
		skb_queue_walk_safe(&ctx->packets, skb, tmp) {
			if (likely(skb_encrypt(skb, ctx->keypair, have_simd))) {
				skb_reset(skb);
			} else {
				__skb_unlink(skb, &ctx->packets);
				dev_kfree_skb(skb);
			}
		}
		/* Dereferencing ctx is unsafe once ctx->state == CTX_FINISHED. */
		peer = peer_rcu_get(ctx->peer);
		atomic_set(&ctx->state, CTX_FINISHED);
		queue_work_on(peer->work_cpu, peer->device->crypt_wq, &peer->send_queue.work);
		peer_put(peer);
	}
	chacha20poly1305_deinit_simd(have_simd);
}

void packet_init_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct wireguard_peer *peer = container_of(queue, struct wireguard_peer, init_queue);

	spin_lock(&peer->init_queue_lock);
	while ((ctx = queue_first_peer(queue)) != NULL) {
		if (unlikely(!packet_initialize_ctx(ctx))) {
			packet_queue_handshake_initiation(peer, false);
			break;
		}
		queue_dequeue(queue);
		if (unlikely(!queue_enqueue_peer(&peer->send_queue, ctx)))
			drop_ctx_and_continue(ctx, true);
		queue_enqueue_shared(peer->device->encrypt_queue, ctx, peer->device->crypt_wq, &peer->device->encrypt_cpu);
	}
	spin_unlock(&peer->init_queue_lock);
}

void packet_create_data(struct wireguard_peer *peer, struct sk_buff_head *packets)
{
	struct crypt_ctx *ctx;
	struct sk_buff *skb;
	struct wireguard_device *wg = peer->device;
	bool need_handshake = false;

	ctx = kmem_cache_alloc(crypt_ctx_cache, GFP_ATOMIC);
	if (unlikely(!ctx)) {
		skb_queue_purge(packets);
		return;
	}
	skb_queue_head_init(&ctx->packets);
	skb_queue_splice_tail(packets, &ctx->packets);
	ctx->peer = peer_rcu_get(peer);
	ctx->keypair = NULL;
	atomic_set(&ctx->state, CTX_NEW);

	/* If there are already packets on the init queue, these must go behind
	 * them to maintain the correct order, so we can only take the fast path
	 * when the queue is empty. */
	if (likely(queue_empty(&peer->init_queue))) {
		if (likely(packet_initialize_ctx(ctx))) {
			if (unlikely(!queue_enqueue_peer(&peer->send_queue, ctx)))
				drop_ctx_and_return(ctx, true);
			queue_enqueue_shared(wg->encrypt_queue, ctx, wg->crypt_wq, &wg->encrypt_cpu);
			return;
		}
		/* Initialization failed, so we need a new keypair. */
		need_handshake = true;
	}

	/* Packets are kept around in the init queue as long as there is an
	 * ongoing handshake. Throw out the oldest packets instead of the new
	 * ones. If we cannot acquire the lock, packets are being dequeued on
	 * another thread. */
	if (unlikely(queue_full(&peer->init_queue)) && spin_trylock(&peer->init_queue_lock)) {
		struct crypt_ctx *tmp = queue_dequeue_peer(&peer->init_queue);
		if (likely(tmp))
			drop_ctx(tmp, true);
		spin_unlock(&peer->init_queue_lock);
	}
	skb_queue_walk(&ctx->packets, skb)
		skb_orphan(skb);
	if (unlikely(!queue_enqueue_peer(&peer->init_queue, ctx)))
		drop_ctx_and_return(ctx, true);
	if (need_handshake)
		packet_queue_handshake_initiation(peer, false);
	/* If we have a valid keypair, but took the slow path because init_queue
	 * had packets on it, init_queue.worker() may have finished
	 * processing the existing packets and returned since we checked if the
	 * init_queue was empty. Run the worker again if this is the only ctx
	 * remaining on the queue. */
	else if (unlikely(queue_first_peer(&peer->init_queue) == ctx))
		queue_work(peer->device->crypt_wq, &peer->init_queue.work);
}

void packet_receive_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct sk_buff *skb;

	while ((ctx = queue_first_peer(queue)) != NULL && atomic_read(&ctx->state) == CTX_FINISHED) {
		queue_dequeue(queue);
		if (likely(skb = ctx->skb)) {
			if (unlikely(!counter_validate(&ctx->keypair->receiving.counter, PACKET_CB(skb)->nonce))) {
				net_dbg_ratelimited("%s: Packet has invalid nonce %Lu (max %Lu)\n", ctx->peer->device->dev->name, PACKET_CB(ctx->skb)->nonce, ctx->keypair->receiving.counter.receive.counter);
				dev_kfree_skb(skb);
			} else {
				skb_reset(skb);
				packet_consume_data_done(skb, ctx->peer, &ctx->endpoint, noise_received_with_keypair(&ctx->peer->keypairs, ctx->keypair));
			}
		}
		noise_keypair_put(ctx->keypair);
		peer_put(ctx->peer);
		kmem_cache_free(crypt_ctx_cache, ctx);
	}
}

void packet_decrypt_worker(struct work_struct *work)
{
	struct crypt_ctx *ctx;
	struct crypt_queue *queue = container_of(work, struct crypt_queue, work);
	struct wireguard_peer *peer;

	while ((ctx = queue_dequeue_shared(queue)) != NULL) {
		if (unlikely(socket_endpoint_from_skb(&ctx->endpoint, ctx->skb) < 0 || !skb_decrypt(ctx->skb, &ctx->keypair->receiving))) {
			dev_kfree_skb(ctx->skb);
			ctx->skb = NULL;
		}
		/* Dereferencing ctx is unsafe once ctx->state == CTX_FINISHED. */
		peer = peer_rcu_get(ctx->peer);
		atomic_set(&ctx->state, CTX_FINISHED);
		queue_work_on(peer->work_cpu, peer->device->crypt_wq, &peer->receive_queue.work);
		peer_put(peer);
	}
}

void packet_consume_data(struct sk_buff *skb, struct wireguard_device *wg)
{
	struct crypt_ctx *ctx;
	__le32 idx = ((struct message_data *)skb->data)->key_idx;

	ctx = kmem_cache_alloc(crypt_ctx_cache, GFP_ATOMIC);
	if (unlikely(!ctx)) {
		dev_kfree_skb(skb);
		return;
	}
	rcu_read_lock_bh();
	ctx->keypair = noise_keypair_get((struct noise_keypair *)index_hashtable_lookup(&wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx));
	rcu_read_unlock_bh();
	if (unlikely(!ctx->keypair)) {
		kmem_cache_free(crypt_ctx_cache, ctx);
		dev_kfree_skb(skb);
		return;
	}
	ctx->skb = skb;
	/* index_hashtable_lookup() already gets a reference to peer. */
	ctx->peer = ctx->keypair->entry.peer;
	atomic_set(&ctx->state, CTX_NEW);

	if (unlikely(!queue_enqueue_peer(&ctx->peer->receive_queue, ctx)))
		drop_ctx_and_return(ctx, false);
	queue_enqueue_shared(wg->decrypt_queue, ctx, wg->crypt_wq, &wg->decrypt_cpu);
}

void peer_purge_queues(struct wireguard_peer *peer)
{
	struct crypt_ctx *ctx;

	if (!spin_trylock(&peer->init_queue_lock))
		return;
	while ((ctx = queue_dequeue_peer(&peer->init_queue)) != NULL)
		drop_ctx(ctx, true);
	spin_unlock(&peer->init_queue_lock);
}
