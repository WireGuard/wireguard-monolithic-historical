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
#include <linux/highmem.h>
#include <crypto/algapi.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static const u8 handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static u8 handshake_init_hash[NOISE_HASH_LEN] __read_mostly;
static u8 handshake_init_chaining_key[NOISE_HASH_LEN] __read_mostly;
static atomic64_t keypair_counter = ATOMIC64_INIT(0);

void noise_init(void)
{
	struct blake2s_state blake;
	blake2s(handshake_init_chaining_key, handshake_name, NULL, NOISE_HASH_LEN, sizeof(handshake_name), 0);
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash, NOISE_HASH_LEN);
}

void noise_handshake_init(struct noise_handshake *handshake, struct noise_static_identity *static_identity, const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN], const u8 peer_preshared_key[NOISE_SYMMETRIC_KEY_LEN], struct wireguard_peer *peer)
{
	memset(handshake, 0, sizeof(struct noise_handshake));
	init_rwsem(&handshake->lock);
	handshake->entry.type = INDEX_HASHTABLE_HANDSHAKE;
	handshake->entry.peer = peer;
	memcpy(handshake->remote_static, peer_public_key, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->preshared_key, peer_preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	handshake->static_identity = static_identity;
	handshake->state = HANDSHAKE_ZEROED;
}

void noise_handshake_clear(struct noise_handshake *handshake)
{
	index_hashtable_remove(&handshake->entry.peer->device->index_hashtable, &handshake->entry);
	down_write(&handshake->lock);
	memset(&handshake->ephemeral_private, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->remote_ephemeral, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->hash, 0, NOISE_HASH_LEN);
	memset(&handshake->chaining_key, 0, NOISE_HASH_LEN);
	handshake->remote_index = 0;
	handshake->state = HANDSHAKE_ZEROED;
	up_write(&handshake->lock);
	index_hashtable_remove(&handshake->entry.peer->device->index_hashtable, &handshake->entry);
}

static struct noise_keypair *keypair_create(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair = kzalloc(sizeof(struct noise_keypair), GFP_KERNEL);
	if (unlikely(!keypair))
		return NULL;
	keypair->internal_id = atomic64_inc_return(&keypair_counter);
	keypair->entry.type = INDEX_HASHTABLE_KEYPAIR;
	keypair->entry.peer = peer;
	kref_init(&keypair->refcount);
	return keypair;
}

static void keypair_free_rcu(struct rcu_head *rcu)
{
	struct noise_keypair *keypair = container_of(rcu, struct noise_keypair, rcu);
	net_dbg_ratelimited("Keypair %Lu destroyed for peer %Lu\n", keypair->internal_id, keypair->entry.peer->internal_id);
	kzfree(keypair);
}

static void keypair_free_kref(struct kref *kref)
{
	struct noise_keypair *keypair = container_of(kref, struct noise_keypair, refcount);
	index_hashtable_remove(&keypair->entry.peer->device->index_hashtable, &keypair->entry);
	call_rcu_bh(&keypair->rcu, keypair_free_rcu);
}

void noise_keypair_put(struct noise_keypair *keypair)
{
	if (unlikely(!keypair))
		return;
	kref_put(&keypair->refcount, keypair_free_kref);
}

struct noise_keypair *noise_keypair_get(struct noise_keypair *keypair)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(), "Calling noise_keypair_get without holding the RCU BH read lock");
	if (unlikely(!keypair || !kref_get_unless_zero(&keypair->refcount)))
		return NULL;
	return keypair;
}

void noise_keypairs_clear(struct noise_keypairs *keypairs)
{
	struct noise_keypair *old;
	mutex_lock(&keypairs->keypair_update_lock);
	old = rcu_dereference_protected(keypairs->previous_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	rcu_assign_pointer(keypairs->previous_keypair, NULL);
	noise_keypair_put(old);
	old = rcu_dereference_protected(keypairs->next_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	rcu_assign_pointer(keypairs->next_keypair, NULL);
	noise_keypair_put(old);
	old = rcu_dereference_protected(keypairs->current_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	rcu_assign_pointer(keypairs->current_keypair, NULL);
	noise_keypair_put(old);
	mutex_unlock(&keypairs->keypair_update_lock);
}

static void add_new_keypair(struct noise_keypairs *keypairs, struct noise_keypair *new_keypair)
{
	struct noise_keypair *previous_keypair, *next_keypair, *current_keypair;

	mutex_lock(&keypairs->keypair_update_lock);
	previous_keypair = rcu_dereference_protected(keypairs->previous_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	next_keypair = rcu_dereference_protected(keypairs->next_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	current_keypair =  rcu_dereference_protected(keypairs->current_keypair, lockdep_is_held(&keypairs->keypair_update_lock));
	if (new_keypair->i_am_the_initiator) {
		/* If we're the initiator, it means we've sent a handshake, and received
		 * a confirmation response, which means this new keypair can now be used. */
		if (next_keypair) {
			/* If there already was a next keypair pending, we demote it to be
			 * the previous keypair, and free the existing current.
			 * TODO: note that this means KCI can result in this transition. It
			 * would perhaps be more sound to always just get rid of the unused
			 * next keypair instead of putting it in the previous slot, but this
			 * might be a bit less robust. Something to think about and decide on. */
			rcu_assign_pointer(keypairs->next_keypair, NULL);
			rcu_assign_pointer(keypairs->previous_keypair, next_keypair);
			noise_keypair_put(current_keypair);
		} else	/* If there wasn't an existing next keypair, we replace the
			 * previous with the current one. */
			rcu_assign_pointer(keypairs->previous_keypair, current_keypair);
		/* At this point we can get rid of the old previous keypair, and set up
		 * the new keypair. */
		noise_keypair_put(previous_keypair);
		rcu_assign_pointer(keypairs->current_keypair, new_keypair);
	} else {
		/* If we're the responder, it means we can't use the new keypair until
		 * we receive confirmation via the first data packet, so we get rid of
		 * the existing previous one, the possibly existing next one, and slide
		 * in the new next one. */
		rcu_assign_pointer(keypairs->next_keypair, new_keypair);
		noise_keypair_put(next_keypair);
		rcu_assign_pointer(keypairs->previous_keypair, NULL);
		noise_keypair_put(previous_keypair);
	}
	mutex_unlock(&keypairs->keypair_update_lock);
}

bool noise_received_with_keypair(struct noise_keypairs *keypairs, struct noise_keypair *received_keypair)
{
	bool ret = false;
	struct noise_keypair *old_keypair;

	/* TODO: probably this needs the actual mutex, but we're in atomic context,
	 * so we can't take it here. Instead we just rely on RCU for the lookups. */
	rcu_read_lock_bh();
	if (unlikely(received_keypair == rcu_dereference_bh(keypairs->next_keypair))) {
		ret = true;
		/* When we've finally received the confirmation, we slide the next
		 * into the current, the current into the previous, and get rid of
		 * the old previous. */
		old_keypair = rcu_dereference_bh(keypairs->previous_keypair);
		rcu_assign_pointer(keypairs->previous_keypair, rcu_dereference_bh(keypairs->current_keypair));
		noise_keypair_put(old_keypair);
		rcu_assign_pointer(keypairs->current_keypair, received_keypair);
		rcu_assign_pointer(keypairs->next_keypair, NULL);
	}
	rcu_read_unlock_bh();

	return ret;
}

void noise_set_static_identity_private_key(struct noise_static_identity *static_identity, const u8 private_key[NOISE_PUBLIC_KEY_LEN])
{
	down_write(&static_identity->lock);
	if (private_key) {
		memcpy(static_identity->static_private, private_key, NOISE_PUBLIC_KEY_LEN);
		static_identity->has_identity = curve25519_generate_public(static_identity->static_public, private_key);
	} else {
		memset(static_identity->static_private, 0, NOISE_PUBLIC_KEY_LEN);
		memset(static_identity->static_public, 0, NOISE_PUBLIC_KEY_LEN);
		static_identity->has_identity = false;
	}
	up_write(&static_identity->lock);
}

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static void kdf(u8 *first_dst, u8 *second_dst, u8 *third_dst, const u8 *data, size_t first_len, size_t second_len, size_t third_len, size_t data_len, const u8 chaining_key[NOISE_HASH_LEN])
{
	u8 secret[BLAKE2S_OUTBYTES];
	u8 output[BLAKE2S_OUTBYTES + 1];
	BUG_ON(first_len > BLAKE2S_OUTBYTES || second_len > BLAKE2S_OUTBYTES || third_len > BLAKE2S_OUTBYTES || ((second_len || second_dst || third_len || third_dst) && (!first_len || !first_dst)) || ((third_len || third_dst) && (!second_len || !second_dst)));

	/* Extract entropy from data into secret */
	blake2s_hmac(secret, data, chaining_key, BLAKE2S_OUTBYTES, data_len, NOISE_HASH_LEN);

	if (!first_dst || !first_len)
		goto out;

	/* Expand first key: key = secret, data = 0x1 */
	output[0] = 1;
	blake2s_hmac(output, output, secret, BLAKE2S_OUTBYTES, 1, BLAKE2S_OUTBYTES);
	memcpy(first_dst, output, first_len);

	if (!second_dst || !second_len)
		goto out;

	/* Expand second key: key = secret, data = first-key || 0x2 */
	output[BLAKE2S_OUTBYTES] = 2;
	blake2s_hmac(output, output, secret, BLAKE2S_OUTBYTES, BLAKE2S_OUTBYTES + 1, BLAKE2S_OUTBYTES);
	memcpy(second_dst, output, second_len);

	if (!third_dst || !third_len)
		goto out;

	/* Expand third key: key = secret, data = second-key || 0x3 */
	output[BLAKE2S_OUTBYTES] = 3;
	blake2s_hmac(output, output, secret, BLAKE2S_OUTBYTES, BLAKE2S_OUTBYTES + 1, BLAKE2S_OUTBYTES);
	memcpy(third_dst, output, third_len);

out:
	/* Clear sensitive data from stack */
	memzero_explicit(secret, BLAKE2S_OUTBYTES);
	memzero_explicit(output, BLAKE2S_OUTBYTES + 1);
}

static void symmetric_key_init(struct noise_symmetric_key *key)
{
	spin_lock_init(&key->counter.receive.lock);
	atomic64_set(&key->counter.counter, 0);
	memset(key->counter.receive.backtrack, 0, sizeof(key->counter.receive.backtrack));
	key->birthdate = get_jiffies_64();
	key->is_valid = true;
}

static void derive_keys(struct noise_symmetric_key *first_dst, struct noise_symmetric_key *second_dst, const u8 chaining_key[NOISE_HASH_LEN])
{
	kdf(first_dst->key, second_dst->key, NULL, NULL, NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0, chaining_key);
	symmetric_key_init(first_dst);
	symmetric_key_init(second_dst);
}

static bool __must_check mix_dh(u8 chaining_key[NOISE_HASH_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 private[NOISE_PUBLIC_KEY_LEN], const u8 public[NOISE_PUBLIC_KEY_LEN])
{
	u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];
	if (unlikely(!curve25519(dh_calculation, private, public)))
		return false;
	kdf(chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
	memzero_explicit(dh_calculation, NOISE_PUBLIC_KEY_LEN);
	return true;
}

static void mix_hash(u8 hash[NOISE_HASH_LEN], const u8 *src, size_t src_len)
{
	struct blake2s_state blake;
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash, NOISE_HASH_LEN);
}

static void mix_psk(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	u8 temp_hash[NOISE_HASH_LEN];
	kdf(chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	mix_hash(hash, temp_hash, NOISE_HASH_LEN);
	memzero_explicit(temp_hash, NOISE_HASH_LEN);
}

static void handshake_init(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN], const u8 remote_static[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void message_encrypt(u8 *dst_ciphertext, const u8 *src_plaintext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
	chacha20poly1305_encrypt(dst_ciphertext, src_plaintext, src_len, hash, NOISE_HASH_LEN, 0 /* Always zero for Noise_IK */, key);
	mix_hash(hash, dst_ciphertext, noise_encrypted_len(src_len));
}

static bool message_decrypt(u8 *dst_plaintext, const u8 *src_ciphertext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
	if (!chacha20poly1305_decrypt(dst_plaintext, src_ciphertext, src_len, hash, NOISE_HASH_LEN, 0 /* Always zero for Noise_IK */, key))
		return false;
	mix_hash(hash, src_ciphertext, src_len);
	return true;
}

static void message_ephemeral(u8 ephemeral_dst[NOISE_PUBLIC_KEY_LEN], const u8 ephemeral_src[NOISE_PUBLIC_KEY_LEN], u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN])
{
	if (ephemeral_dst != ephemeral_src)
		memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	mix_hash(hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
}

static void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN])
{
	struct timeval now;
	do_gettimeofday(&now);
	/* https://cr.yp.to/libtai/tai64.html */
	*(__be64 *)output = cpu_to_be64(4611686018427387914ULL + now.tv_sec);
	*(__be32 *)(output + sizeof(__be64)) = cpu_to_be32(1000 * now.tv_usec + 500);
}

bool noise_handshake_create_initiation(struct message_handshake_initiation *dst, struct noise_handshake *handshake)
{
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;

	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

	if (unlikely(!handshake->static_identity->has_identity))
		goto out;

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);

	handshake_init(handshake->chaining_key, handshake->hash, handshake->remote_static);

	/* e */
	curve25519_generate_secret(handshake->ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral, handshake->ephemeral_private))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral, dst->unencrypted_ephemeral, handshake->chaining_key, handshake->hash);

	/* es */
	if (!mix_dh(handshake->chaining_key, key, handshake->ephemeral_private, handshake->remote_static))
		goto out;

	/* s */
	message_encrypt(dst->encrypted_static, handshake->static_identity->static_public, NOISE_PUBLIC_KEY_LEN, key, handshake->hash);

	/* ss */
	if (!mix_dh(handshake->chaining_key, key, handshake->static_identity->static_private, handshake->remote_static))
		goto out;

	/* {t} */
	tai64n_now(timestamp);
	message_encrypt(dst->encrypted_timestamp, timestamp, NOISE_TIMESTAMP_LEN, key, handshake->hash);

	dst->sender_index = index_hashtable_insert(&handshake->entry.peer->device->index_hashtable, &handshake->entry);

	ret = true;
	handshake->state = HANDSHAKE_CREATED_INITIATION;

out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	return ret;
}

struct wireguard_peer *noise_handshake_consume_initiation(struct message_handshake_initiation *src, struct wireguard_device *wg)
{
	bool replay_attack, flood_attack;
	u8 s[NOISE_PUBLIC_KEY_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 t[NOISE_TIMESTAMP_LEN];
	struct noise_handshake *handshake;
	struct wireguard_peer *wg_peer = NULL;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];

	down_read(&wg->static_identity.lock);
	if (unlikely(!wg->static_identity.has_identity))
		goto out;

	handshake_init(chaining_key, hash, wg->static_identity.static_public);

	/* e */
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

	/* es */
	if (!mix_dh(chaining_key, key, wg->static_identity.static_private, e))
		goto out;

	/* s */
	if (!message_decrypt(s, src->encrypted_static, sizeof(src->encrypted_static), key, hash))
		goto out;

	/* ss */
	if (!mix_dh(chaining_key, key, wg->static_identity.static_private, s))
		goto out;

	/* {t} */
	if (!message_decrypt(t, src->encrypted_timestamp, sizeof(src->encrypted_timestamp), key, hash))
		goto out;

	/* Lookup which peer we're actually talking to */
	wg_peer = pubkey_hashtable_lookup(&wg->peer_hashtable, s);
	if (!wg_peer)
		goto out;
	handshake = &wg_peer->handshake;
	down_read(&handshake->lock);
	replay_attack = memcmp(t, handshake->latest_timestamp, NOISE_TIMESTAMP_LEN) <= 0;
	flood_attack = !time_is_before_jiffies64(handshake->last_initiation_consumption + INITIATIONS_PER_SECOND);
	up_read(&handshake->lock);
	if (replay_attack || flood_attack) {
		peer_put(wg_peer);
		wg_peer = NULL;
		goto out;
	}

	/* Success! Copy everything to peer */
	down_write(&handshake->lock);
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	handshake->last_initiation_consumption = get_jiffies_64();
	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
	up_write(&handshake->lock);

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	up_read(&wg->static_identity.lock);
	return wg_peer;
}

bool noise_handshake_create_response(struct message_handshake_response *dst, struct noise_handshake *handshake)
{
	bool ret = false;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	down_read(&handshake->static_identity->lock);
	down_write(&handshake->lock);

	if (handshake->state != HANDSHAKE_CONSUMED_INITIATION)
		goto out;

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE);
	dst->receiver_index = handshake->remote_index;

	/* e */
	curve25519_generate_secret(handshake->ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral, handshake->ephemeral_private))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral, dst->unencrypted_ephemeral, handshake->chaining_key, handshake->hash);

	/* ee */
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private, handshake->remote_ephemeral))
		goto out;

	/* se */
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private, handshake->remote_static))
		goto out;

	/* psk */
	mix_psk(handshake->chaining_key, handshake->hash, key, handshake->preshared_key);

	/* {} */
	message_encrypt(dst->encrypted_nothing, NULL, 0, key, handshake->hash);

	dst->sender_index = index_hashtable_insert(&handshake->entry.peer->device->index_hashtable, &handshake->entry);

	handshake->state = HANDSHAKE_CREATED_RESPONSE;
	ret = true;

out:
	up_write(&handshake->lock);
	up_read(&handshake->static_identity->lock);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	return ret;
}

struct wireguard_peer *noise_handshake_consume_response(struct message_handshake_response *src, struct wireguard_device *wg)
{
	struct noise_handshake *handshake;
	struct wireguard_peer *ret_peer = NULL;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	u8 static_private[NOISE_PUBLIC_KEY_LEN];
	enum noise_handshake_state state = HANDSHAKE_ZEROED;

	down_read(&wg->static_identity.lock);

	if (unlikely(!wg->static_identity.has_identity))
		goto out;

	handshake = (struct noise_handshake *)index_hashtable_lookup(&wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE, src->receiver_index);
	if (unlikely(!handshake))
		goto out;

	down_read(&handshake->lock);
	state = handshake->state;
	memcpy(hash, handshake->hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
	memcpy(ephemeral_private, handshake->ephemeral_private, NOISE_PUBLIC_KEY_LEN);
	up_read(&handshake->lock);

	if (state != HANDSHAKE_CREATED_INITIATION)
		goto fail;

	/* e */
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

	/* ee */
	if (!mix_dh(chaining_key, NULL, ephemeral_private, e))
		goto out;

	/* se */
	if (!mix_dh(chaining_key, NULL, wg->static_identity.static_private, e))
		goto out;

	/* psk */
	mix_psk(chaining_key, hash, key, handshake->preshared_key);

	/* {} */
	if (!message_decrypt(NULL, src->encrypted_nothing, sizeof(src->encrypted_nothing), key, hash))
		goto fail;

	/* Success! Copy everything to peer */
	down_write(&handshake->lock);
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->remote_index = src->sender_index;
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
	up_write(&handshake->lock);
	ret_peer = handshake->entry.peer;
	goto out;

fail:
	peer_put(handshake->entry.peer);
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	memzero_explicit(ephemeral_private, NOISE_PUBLIC_KEY_LEN);
	memzero_explicit(static_private, NOISE_PUBLIC_KEY_LEN);
	up_read(&wg->static_identity.lock);
	return ret_peer;
}

bool noise_handshake_begin_session(struct noise_handshake *handshake, struct noise_keypairs *keypairs, bool i_am_the_initiator)
{
	struct noise_keypair *new_keypair;

	down_read(&handshake->lock);
	if (handshake->state != HANDSHAKE_CREATED_RESPONSE && handshake->state != HANDSHAKE_CONSUMED_RESPONSE)
		goto fail;

	new_keypair = keypair_create(handshake->entry.peer);
	if (!new_keypair)
		goto fail;
	new_keypair->i_am_the_initiator = i_am_the_initiator;
	new_keypair->remote_index = handshake->remote_index;

	if (i_am_the_initiator)
		derive_keys(&new_keypair->sending, &new_keypair->receiving, handshake->chaining_key);
	else
		derive_keys(&new_keypair->receiving, &new_keypair->sending, handshake->chaining_key);
	up_read(&handshake->lock);

	add_new_keypair(keypairs, new_keypair);
	index_hashtable_replace(&handshake->entry.peer->device->index_hashtable, &handshake->entry, &new_keypair->entry);
	noise_handshake_clear(handshake);
	net_dbg_ratelimited("Keypair %Lu created for peer %Lu\n", new_keypair->internal_id, new_keypair->entry.peer->internal_id);

	return true;

fail:
	up_read(&handshake->lock);
	return false;
}
