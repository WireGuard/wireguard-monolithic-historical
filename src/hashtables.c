/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "hashtables.h"
#include "peer.h"
#include "noise.h"

static u32 pubkey_hashfn(const void *data, u32 len, u32 seed)
{
	/* The rhashtable API only allows 32 bits of seed, while siphash expects 128 bits. */
	siphash_key_t key = { .key = { seed } };

	return siphash(data, len, &key);
}

static const struct rhashtable_params pubkey_params = {
	.key_offset = offsetof(struct wireguard_peer, handshake.remote_static),
	.key_len = FIELD_SIZEOF(struct wireguard_peer, handshake.remote_static),
	.head_offset = offsetof(struct wireguard_peer, pubkey_hash),
	.hashfn = pubkey_hashfn,
	.automatic_shrinking = true,
};

int pubkey_hashtable_init(struct pubkey_hashtable *table)
{
	return rhashtable_init(&table->hashtable, &pubkey_params);
}

void pubkey_hashtable_cleanup(struct pubkey_hashtable *table)
{
	rhashtable_destroy(&table->hashtable);
}

void pubkey_hashtable_add(struct pubkey_hashtable *table, struct wireguard_peer *peer)
{
	/* TODO: does this really work with hash collisions? */
	rhashtable_insert_fast(&table->hashtable, &peer->pubkey_hash, pubkey_params);
}

void pubkey_hashtable_remove(struct pubkey_hashtable *table, struct wireguard_peer *peer)
{
	rhashtable_remove_fast(&table->hashtable, &peer->pubkey_hash, pubkey_params);
}

/* Returns a strong reference to a peer */
struct wireguard_peer *pubkey_hashtable_lookup(struct pubkey_hashtable *table, const u8 pubkey[NOISE_PUBLIC_KEY_LEN])
{
	struct wireguard_peer *peer;

	rcu_read_lock_bh();
	peer = peer_get(rhashtable_lookup_fast(&table->hashtable, pubkey, pubkey_params));
	rcu_read_unlock_bh();

	return peer;
}

static u32 index_hashfn(const void *data, u32 len, u32 seed)
{
	BUG_ON(len != 4);
	return *(u32 *)data;
}

static const struct rhashtable_params index_params = {
	.key_offset = offsetof(struct index_hashtable_entry, index),
	.key_len = FIELD_SIZEOF(struct index_hashtable_entry, index),
	.head_offset = offsetof(struct index_hashtable_entry, index_hash),
	.hashfn = index_hashfn,
	.automatic_shrinking = true,
};

int index_hashtable_init(struct index_hashtable *table)
{
	int ret;

	ret = rhashtable_init(&table->hashtable, &index_params);
	spin_lock_init(&table->lock);
	return ret;
}

void index_hashtable_cleanup(struct index_hashtable *table)
{
	rhashtable_destroy(&table->hashtable);
}


/* At the moment, we limit ourselves to 2^20 total peers, which generally might amount to 2^20*3
 * items in this hashtable. The algorithm below works by picking a random number and testing it.
 * We can see that these limits mean we usually succeed pretty quickly:
 *
 * >>> def calculation(tries, size):
 * ...     return (size / 2**32)**(tries - 1) *  (1 - (size / 2**32))
 * ...
 * >>> calculation(1, 2**20 * 3)
 * 0.999267578125
 * >>> calculation(2, 2**20 * 3)
 * 0.0007318854331970215
 * >>> calculation(3, 2**20 * 3)
 * 5.360489012673497e-07
 * >>> calculation(4, 2**20 * 3)
 * 3.9261394135792216e-10
 *
 * At the moment, we don't do any masking, so this algorithm isn't exactly constant time in
 * either the random guessing or in the hash list lookup. We could require a minimum of 3
 * tries, which would successfully mask the guessing. TODO: this would not, however, help
 * with the growing hash lengths.
 */

__le32 index_hashtable_insert(struct index_hashtable *table, struct index_hashtable_entry *entry)
{
	struct index_hashtable_entry *existing_entry;

	rcu_read_lock_bh();

search_unused_slot:
	/* First we try to find an unused slot, randomly, while unlocked. */
	entry->index = (__force __le32)get_random_u32();
	existing_entry = rhashtable_lookup_fast(&table->hashtable, &entry->index, index_params);
	if (existing_entry && existing_entry->index == entry->index) {
		goto search_unused_slot; /* If it's already in use, we continue searching. */
	}

	/* Once we've found an unused slot, we lock it, and then double-check
	 * that nobody else stole it from us.
	 */
	spin_lock_bh(&table->lock);
	existing_entry = rhashtable_lookup_fast(&table->hashtable, &entry->index, index_params);
	if (existing_entry && existing_entry->index == entry->index) {
		spin_unlock_bh(&table->lock);
		goto search_unused_slot; /* If it was stolen, we start over. */
	}

	/* Otherwise, we know we have it exclusively (since we're locked), so we insert. */
	rhashtable_insert_fast(&table->hashtable, &entry->index_hash, index_params);
	spin_unlock_bh(&table->lock);

	rcu_read_unlock_bh();

	return entry->index;
}

bool index_hashtable_replace(struct index_hashtable *table, struct index_hashtable_entry *old, struct index_hashtable_entry *new)
{
	int ret;

	if (unlikely(rhashtable_lookup_fast(&table->hashtable, old, index_params)))
		return false;

	spin_lock_bh(&table->lock);
	new->index = old->index;
	ret = rhashtable_replace_fast(&table->hashtable, &old->index_hash, &new->index_hash, index_params);
	WARN_ON_ONCE(ret != 0);
	spin_unlock_bh(&table->lock);
	return true;
}

void index_hashtable_remove(struct index_hashtable *table, struct index_hashtable_entry *entry)
{
	spin_lock_bh(&table->lock);
	rhashtable_remove_fast(&table->hashtable, &entry->index_hash, index_params);
	spin_unlock_bh(&table->lock);
}

/* Returns a strong reference to a entry->peer */
struct index_hashtable_entry *index_hashtable_lookup(struct index_hashtable *table, const enum index_hashtable_type type_mask, const __le32 index)
{
	struct index_hashtable_entry *entry = NULL;

	rcu_read_lock_bh();
	entry = rhashtable_lookup_fast(&table->hashtable, &index, index_params);
	if (likely(entry && entry->type & type_mask)) {
		entry->peer = peer_get(entry->peer);
		if (unlikely(!entry->peer))
			entry = NULL;
	}
	rcu_read_unlock_bh();
	return entry;
}
