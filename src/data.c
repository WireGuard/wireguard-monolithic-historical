/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "noise.h"
#include "device.h"
#include "peer.h"
#include "messages.h"
#include "packets.h"
#include "hashtables.h"

#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/scatterlist.h>
#include <net/ip_tunnels.h>
#include <net/xfrm.h>
#include <crypto/algapi.h>

struct encryption_ctx {
	struct padata_priv padata;
	struct sk_buff_head queue;
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
};

struct decryption_ctx {
	struct padata_priv padata;
	struct endpoint endpoint;
	struct sk_buff *skb;
	struct noise_keypair *keypair;
};

#ifdef CONFIG_WIREGUARD_PARALLEL
static struct kmem_cache *encryption_ctx_cache __read_mostly;
static struct kmem_cache *decryption_ctx_cache __read_mostly;

int packet_init_data_caches(void)
{
	encryption_ctx_cache = kmem_cache_create("wireguard_encryption_ctx", sizeof(struct encryption_ctx), 0, 0, NULL);
	if (!encryption_ctx_cache)
		return -ENOMEM;
	decryption_ctx_cache = kmem_cache_create("wireguard_decryption_ctx", sizeof(struct decryption_ctx), 0, 0, NULL);
	if (!decryption_ctx_cache) {
		kmem_cache_destroy(encryption_ctx_cache);
		return -ENOMEM;
	}
	return 0;
}

void packet_deinit_data_caches(void)
{
	kmem_cache_destroy(encryption_ctx_cache);
	kmem_cache_destroy(decryption_ctx_cache);
}
#endif

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

	index = their_counter >> ilog2(COUNTER_REDUNDANT_BITS);

	if (likely(their_counter > counter->receive.counter)) {
		index_current = counter->receive.counter >> ilog2(COUNTER_REDUNDANT_BITS);
		top = min_t(unsigned long, index - index_current, COUNTER_BITS_TOTAL / BITS_PER_LONG);
		for (i = 1; i <= top; ++i)
			counter->receive.backtrack[(i + index_current) & ((COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1)] = 0;
		counter->receive.counter = their_counter;
	}

	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;
	ret = !test_and_set_bit(their_counter & (COUNTER_REDUNDANT_BITS - 1), &counter->receive.backtrack[index]);

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

	return pskb_trim(skb, skb->len - noise_encrypted_len(0)) == 0;
}

static inline bool get_encryption_nonce(u64 *nonce, struct noise_symmetric_key *key)
{
	if (unlikely(!key))
		return false;

	if (unlikely(!key->is_valid || time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME))) {
		key->is_valid = false;
		return false;
	}

	*nonce = atomic64_inc_return(&key->counter.counter) - 1;
	if (*nonce >= REJECT_AFTER_MESSAGES) {
		key->is_valid = false;
		return false;
	}

	return true;
}

static inline void queue_encrypt_reset(struct sk_buff_head *queue, struct noise_keypair *keypair)
{
	struct sk_buff *skb, *tmp;
	bool have_simd = chacha20poly1305_init_simd();
	skb_queue_walk_safe(queue, skb, tmp) {
		if (unlikely(!skb_encrypt(skb, keypair, have_simd))) {
			__skb_unlink(skb, queue);
			kfree_skb(skb);
			continue;
		}
		skb_reset(skb);
	}
	chacha20poly1305_deinit_simd(have_simd);
	noise_keypair_put(keypair);
}

#ifdef CONFIG_WIREGUARD_PARALLEL
static void begin_parallel_encryption(struct padata_priv *padata)
{
	struct encryption_ctx *ctx = container_of(padata, struct encryption_ctx, padata);
	queue_encrypt_reset(&ctx->queue, ctx->keypair);
	padata_do_serial(padata);
}

static void finish_parallel_encryption(struct padata_priv *padata)
{
	struct encryption_ctx *ctx = container_of(padata, struct encryption_ctx, padata);
	packet_create_data_done(&ctx->queue, ctx->peer);
	atomic_dec(&ctx->peer->parallel_encryption_inflight);
	peer_put(ctx->peer);
	kmem_cache_free(encryption_ctx_cache, ctx);
}

static inline unsigned int choose_cpu(__le32 key)
{
	unsigned int cpu_index, cpu, cb_cpu;

	/* This ensures that packets encrypted to the same key are sent in-order. */
	cpu_index = ((__force unsigned int)key) % cpumask_weight(cpu_online_mask);
	cb_cpu = cpumask_first(cpu_online_mask);
	for (cpu = 0; cpu < cpu_index; ++cpu)
		cb_cpu = cpumask_next(cb_cpu, cpu_online_mask);

	return cb_cpu;
}
#endif

int packet_create_data(struct sk_buff_head *queue, struct wireguard_peer *peer)
{
	int ret = -ENOKEY;
	struct noise_keypair *keypair;
	struct sk_buff *skb;

	rcu_read_lock_bh();
	keypair = noise_keypair_get(rcu_dereference_bh(peer->keypairs.current_keypair));
	if (unlikely(!keypair))
		goto err_rcu;
	rcu_read_unlock_bh();

	skb_queue_walk(queue, skb) {
		if (unlikely(!get_encryption_nonce(&PACKET_CB(skb)->nonce, &keypair->sending)))
			goto err;

		/* After the first time through the loop, if we've suceeded with a legitimate nonce,
		 * then we don't want a -ENOKEY error if subsequent nonces fail. Rather, if this
		 * condition arises, we simply want error out hard, and drop the entire queue. This
		 * is partially lazy programming and TODO: this could be made to only requeue the
		 * ones that had no nonce. But I'm not sure it's worth the added complexity, given
		 * how rarely that condition should arise. */
		ret = -EPIPE;
	}

#ifdef CONFIG_WIREGUARD_PARALLEL
	if ((skb_queue_len(queue) > 1 || queue->next->len > 256 || atomic_read(&peer->parallel_encryption_inflight) > 0) && cpumask_weight(cpu_online_mask) > 1) {
		struct encryption_ctx *ctx = kmem_cache_alloc(encryption_ctx_cache, GFP_ATOMIC);
		if (!ctx)
			goto serial_encrypt;
		skb_queue_head_init(&ctx->queue);
		skb_queue_splice_init(queue, &ctx->queue);
		memset(&ctx->padata, 0, sizeof(ctx->padata));
		ctx->padata.parallel = begin_parallel_encryption;
		ctx->padata.serial = finish_parallel_encryption;
		ctx->keypair = keypair;
		ctx->peer = peer_rcu_get(peer);
		ret = -EBUSY;
		if (unlikely(!ctx->peer))
			goto err_parallel;
		atomic_inc(&peer->parallel_encryption_inflight);
		if (unlikely(padata_do_parallel(peer->device->encrypt_pd, &ctx->padata, choose_cpu(keypair->remote_index)))) {
			atomic_dec(&peer->parallel_encryption_inflight);
			peer_put(ctx->peer);
err_parallel:
			skb_queue_splice(&ctx->queue, queue);
			kmem_cache_free(encryption_ctx_cache, ctx);
			goto err;
		}
	} else
serial_encrypt:
#endif
	{
		queue_encrypt_reset(queue, keypair);
		packet_create_data_done(queue, peer);
	}
	return 0;

err:
	noise_keypair_put(keypair);
	return ret;
err_rcu:
	rcu_read_unlock_bh();
	return ret;
}

static void begin_decrypt_packet(struct decryption_ctx *ctx)
{
	if (unlikely(socket_endpoint_from_skb(&ctx->endpoint, ctx->skb) < 0 || !skb_decrypt(ctx->skb, &ctx->keypair->receiving))) {
		peer_put(ctx->keypair->entry.peer);
		noise_keypair_put(ctx->keypair);
		dev_kfree_skb(ctx->skb);
		ctx->skb = NULL;
	}
}

static void finish_decrypt_packet(struct decryption_ctx *ctx)
{
	bool used_new_key;

	if (!ctx->skb)
		return;

	if (unlikely(!counter_validate(&ctx->keypair->receiving.counter, PACKET_CB(ctx->skb)->nonce))) {
		net_dbg_ratelimited("Packet has invalid nonce %Lu (max %Lu)\n", PACKET_CB(ctx->skb)->nonce, ctx->keypair->receiving.counter.receive.counter);
		peer_put(ctx->keypair->entry.peer);
		noise_keypair_put(ctx->keypair);
		dev_kfree_skb(ctx->skb);
		return;
	}

	used_new_key = noise_received_with_keypair(&ctx->keypair->entry.peer->keypairs, ctx->keypair);
	skb_reset(ctx->skb);
	packet_consume_data_done(ctx->skb, ctx->keypair->entry.peer, &ctx->endpoint, used_new_key);
	noise_keypair_put(ctx->keypair);
}

#ifdef CONFIG_WIREGUARD_PARALLEL
static void begin_parallel_decryption(struct padata_priv *padata)
{
	struct decryption_ctx *ctx = container_of(padata, struct decryption_ctx, padata);
	begin_decrypt_packet(ctx);
	padata_do_serial(padata);
}

static void finish_parallel_decryption(struct padata_priv *padata)
{
	struct decryption_ctx *ctx = container_of(padata, struct decryption_ctx, padata);
	finish_decrypt_packet(ctx);
	kmem_cache_free(decryption_ctx_cache, ctx);
}
#endif

void packet_consume_data(struct sk_buff *skb, struct wireguard_device *wg)
{
	struct noise_keypair *keypair;
	__le32 idx = ((struct message_data *)skb->data)->key_idx;

	rcu_read_lock_bh();
	keypair = noise_keypair_get((struct noise_keypair *)index_hashtable_lookup(&wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx));
	rcu_read_unlock_bh();
	if (unlikely(!keypair))
		goto err;

#ifdef CONFIG_WIREGUARD_PARALLEL
	if (cpumask_weight(cpu_online_mask) > 1) {
		struct decryption_ctx *ctx = kmem_cache_alloc(decryption_ctx_cache, GFP_ATOMIC);
		if (unlikely(!ctx))
			goto err_peer;
		ctx->skb = skb;
		ctx->keypair = keypair;
		memset(&ctx->padata, 0, sizeof(ctx->padata));
		ctx->padata.parallel = begin_parallel_decryption;
		ctx->padata.serial = finish_parallel_decryption;
		if (unlikely(padata_do_parallel(wg->decrypt_pd, &ctx->padata, choose_cpu(idx)))) {
			kmem_cache_free(decryption_ctx_cache, ctx);
			goto err_peer;
		}
	} else
#endif
	{
		struct decryption_ctx ctx = {
			.skb = skb,
			.keypair = keypair
		};
		begin_decrypt_packet(&ctx);
		finish_decrypt_packet(&ctx);
	}
	return;

#ifdef CONFIG_WIREGUARD_PARALLEL
err_peer:
	peer_put(keypair->entry.peer);
	noise_keypair_put(keypair);
#endif
err:
	dev_kfree_skb(skb);
}
