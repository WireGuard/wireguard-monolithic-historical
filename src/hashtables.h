/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef HASHTABLES_H
#define HASHTABLES_H

#include "messages.h"
#include "crypto/siphash24.h"

#include <linux/hashtable.h>
#include <linux/mutex.h>

struct wireguard_peer;

struct pubkey_hashtable {
	DECLARE_HASHTABLE(hashtable, 8);
	uint8_t key[SIPHASH24_KEY_LEN];
	struct mutex lock;
};

void pubkey_hashtable_init(struct pubkey_hashtable *table);
void pubkey_hashtable_add(struct pubkey_hashtable *table, struct wireguard_peer *peer);
void pubkey_hashtable_remove(struct pubkey_hashtable *table, struct wireguard_peer *peer);
struct wireguard_peer *pubkey_hashtable_lookup(struct pubkey_hashtable *table, const uint8_t pubkey[NOISE_PUBLIC_KEY_LEN]);

struct index_hashtable {
	DECLARE_HASHTABLE(hashtable, 10);
	uint8_t key[SIPHASH24_KEY_LEN];
	spinlock_t lock;
};

enum index_hashtable_type {
	INDEX_HASHTABLE_HANDSHAKE = (1 << 0),
	INDEX_HASHTABLE_KEYPAIR = (1 << 1)
};

struct index_hashtable_entry {
	struct wireguard_peer *peer;
	struct hlist_node index_hash;
	enum index_hashtable_type type;
	__le32 index;
};
void index_hashtable_init(struct index_hashtable *table);
__le32 index_hashtable_insert(struct index_hashtable *table, struct index_hashtable_entry *entry);
void index_hashtable_replace(struct index_hashtable *table, struct index_hashtable_entry *old, struct index_hashtable_entry *new);
void index_hashtable_remove(struct index_hashtable *table, struct index_hashtable_entry *entry);
struct index_hashtable_entry *index_hashtable_lookup(struct index_hashtable *table, const enum index_hashtable_type type_mask, const __le32 index);

#endif
