/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "hashtables.h"
#include "peer.h"
#include "noise.h"
#include "crypto/siphash24.h"

#include <linux/hashtable.h>

static inline struct hlist_head *pubkey_bucket(struct pubkey_hashtable *table, const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN])
{
	/* siphash24 gives us a secure 64bit number based on a random key. Since the bits are
	 * uniformly distributed, we can then mask off to get the bits we need. */
	return &table->hashtable[siphash24(pubkey, NOISE_PUBLIC_KEY_LEN, table->key) & (HASH_SIZE(table->hashtable) - 1)];
}

void pubkey_hashtable_init(struct pubkey_hashtable *table)
{
	get_random_bytes(table->key, SIPHASH24_KEY_LEN);
	hash_init(table->hashtable);
	mutex_init(&table->lock);
}

void pubkey_hashtable_add(struct pubkey_hashtable *table, struct wireguard_peer *peer)
{
	mutex_lock(&table->lock);
	hlist_add_head_rcu(&peer->pubkey_hash, pubkey_bucket(table, peer->handshake.remote_static));
	mutex_unlock(&table->lock);
}

void pubkey_hashtable_remove(struct pubkey_hashtable *table, struct wireguard_peer *peer)
{
	mutex_lock(&table->lock);
	hlist_del_init_rcu(&peer->pubkey_hash);
	mutex_unlock(&table->lock);
}

/* Returns a strong reference to a peer */
struct wireguard_peer *pubkey_hashtable_lookup(struct pubkey_hashtable *table, const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN])
{
	struct wireguard_peer *iter_peer, *peer = NULL;
	rcu_read_lock();
	hlist_for_each_entry_rcu(iter_peer, pubkey_bucket(table, pubkey), pubkey_hash) {
		if (!memcmp(pubkey, iter_peer->handshake.remote_static, NOISE_PUBLIC_KEY_LEN)) {
			peer = iter_peer;
			break;
		}
	}
	peer = peer_get(peer);
	rcu_read_unlock();
	return peer;
}

static inline struct hlist_head *index_bucket(struct index_hashtable *table, const __le32 index)
{
	/* Since the indices are random and thus all bits are uniformly distributed,
	 * we can find its bucket simply by masking. */
	return &table->hashtable[(__force u32)index & (HASH_SIZE(table->hashtable) - 1)];
}

void index_hashtable_init(struct index_hashtable *table)
{
	get_random_bytes(table->key, SIPHASH24_KEY_LEN);
	hash_init(table->hashtable);
	spin_lock_init(&table->lock);
}

__le32 index_hashtable_insert(struct index_hashtable *table, struct index_hashtable_entry *entry)
{
	struct index_hashtable_entry *existing_entry;
	uint64_t rand;

	spin_lock(&table->lock);
	hlist_del_init_rcu(&entry->index_hash);
	spin_unlock(&table->lock);

	rcu_read_lock();

search_unused_slot:
	/* First we try to find an unused slot, randomly, while unlocked. */
	rand = get_random_long();
	entry->index = (__force __le32)siphash24((uint8_t *)&rand, sizeof(rand), table->key);
	hlist_for_each_entry_rcu(existing_entry, index_bucket(table, entry->index), index_hash) {
		if (existing_entry->index == entry->index)
			goto search_unused_slot; /* If it's already in use, we continue searching. */
	}

	/* Once we've found an unused slot, we lock it, and then double-check
	 * that nobody else stole it from us. */
	spin_lock(&table->lock);
	hlist_for_each_entry_rcu(existing_entry, index_bucket(table, entry->index), index_hash) {
		if (existing_entry->index == entry->index) {
			spin_unlock(&table->lock);
			goto search_unused_slot; /* If it was stolen, we start over. */
		}
	}
	/* Otherwise, we know we have it exclusively (since we're locked), so we insert. */
	hlist_add_head_rcu(&entry->index_hash, index_bucket(table, entry->index));
	spin_unlock(&table->lock);

	rcu_read_unlock();

	return entry->index;
}

void index_hashtable_replace(struct index_hashtable *table, struct index_hashtable_entry *old, struct index_hashtable_entry *new)
{
	spin_lock(&table->lock);
	new->index = old->index;
	hlist_replace_rcu(&old->index_hash, &new->index_hash);
	INIT_HLIST_NODE(&old->index_hash);
	spin_unlock(&table->lock);
}

void index_hashtable_remove(struct index_hashtable *table, struct index_hashtable_entry *entry)
{
	spin_lock(&table->lock);
	hlist_del_init_rcu(&entry->index_hash);
	spin_unlock(&table->lock);
}

/* Returns a strong reference to a entry->peer */
struct index_hashtable_entry *index_hashtable_lookup(struct index_hashtable *table, const enum index_hashtable_type type_mask, const __le32 index)
{
	struct index_hashtable_entry *iter_entry, *entry = NULL;
	rcu_read_lock();
	hlist_for_each_entry_rcu(iter_entry, index_bucket(table, index), index_hash) {
		if (iter_entry->index == index && (iter_entry->type & type_mask)) {
			entry = iter_entry;
			break;
		}
	}
	if (likely(entry)) {
		entry->peer = peer_get(entry->peer);
		if (unlikely(!entry->peer))
			entry = NULL;
	}
	rcu_read_unlock();
	return entry;
}
