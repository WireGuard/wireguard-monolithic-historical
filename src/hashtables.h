/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef HASHTABLES_H
#define HASHTABLES_H

#include <linux/hashtable.h>
#include <linux/mutex.h>
#include "crypto/siphash24.h"

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
	atomic64_t counter;
	spinlock_t lock;
};
struct index_hashtable_entry;

void index_hashtable_init(struct index_hashtable *table);
__le32 index_hashtable_insert(struct index_hashtable *table, struct index_hashtable_entry *entry);
void index_hashtable_replace(struct index_hashtable *table, struct index_hashtable_entry *old, struct index_hashtable_entry *new);
void index_hashtable_remove(struct index_hashtable *table, struct index_hashtable_entry *entry);
struct index_hashtable_entry *index_hashtable_lookup(struct index_hashtable *table, const enum index_hashtable_type type_mask, const __le32 index);

#endif
