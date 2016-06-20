/*
 * Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * See doc/protocol.md and https://github.com/trevp/noise/blob/master/noise.md for more info
 */

#ifndef NOISE_H
#define NOISE_H

#include "crypto/curve25519.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/blake2s.h"
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>

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

enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_POINT_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEYLEN,
	NOISE_TIMESTAMP_LEN = sizeof(u64) + sizeof(u32),
	NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAGLEN,
	NOISE_HASH_LEN = BLAKE2S_OUTBYTES
};

enum counter_values {
	COUNTER_BITS_TOTAL = 2048,
	COUNTER_REDUNDANT_BITS = BITS_PER_LONG,
	COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS
};

enum wireguard_limits {
	REKEY_AFTER_MESSAGES = U64_MAX - 0xffff,
	REJECT_AFTER_MESSAGES = U64_MAX - COUNTER_WINDOW_SIZE - 1,
	REKEY_TIMEOUT = 5 * HZ,
	REKEY_AFTER_TIME = 120 * HZ,
	REJECT_AFTER_TIME = 180 * HZ,
	INITIATIONS_PER_SECOND = HZ / 50,
	MAX_PEERS_PER_DEVICE = U16_MAX
};

union noise_counter {
	struct {
		u64 counter;
		unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG];
		spinlock_t lock;
	} receive;
	atomic64_t counter;
};

struct noise_symmetric_key {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	union noise_counter counter;
	uint64_t birthdate;
	bool is_valid;
};

struct noise_keypair {
	struct index_hashtable_entry entry;
	struct noise_symmetric_key sending;
	struct noise_symmetric_key receiving;
	__le32 remote_index;
	bool i_am_the_initiator;
	struct kref refcount;
	struct rcu_head rcu;
	uint64_t internal_id;
};

struct noise_keypairs {
	struct noise_keypair __rcu *current_keypair;
	struct noise_keypair __rcu *previous_keypair;
	struct noise_keypair __rcu *next_keypair;
	struct mutex keypair_update_lock;
};

struct noise_static_identity {
	bool has_identity, has_psk;
	u8 static_public[NOISE_PUBLIC_KEY_LEN];
	u8 static_private[NOISE_PUBLIC_KEY_LEN];
	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	struct rw_semaphore lock;
};

enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE
};

struct noise_handshake {
	struct index_hashtable_entry entry;

	enum noise_handshake_state state;
	uint64_t last_initiation_consumption;

	struct noise_static_identity *static_identity;

	u8 ephemeral_public[NOISE_PUBLIC_KEY_LEN];
	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];

	u8 remote_static[NOISE_PUBLIC_KEY_LEN];
	u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];

	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];

	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
	__le32 remote_index;

	/* Protects all members except the immutable (after noise_peer_init): remote_static, static_identity */
	struct rw_semaphore lock;
};

#define noise_encrypted_len(plain_len) (plain_len + NOISE_AUTHTAG_LEN)

struct wireguard_peer;
struct wireguard_device;
struct message_header;
struct message_handshake_initiation;
struct message_handshake_response;
struct message_data;
struct message_handshake_cookie;

void noise_init(void);
void noise_handshake_init(struct noise_handshake *handshake, struct noise_static_identity *static_identity, const u8 peer_public_key[NOISE_PUBLIC_KEY_LEN], struct wireguard_peer *peer);
void noise_handshake_clear(struct noise_handshake *handshake);
void noise_keypair_put(struct noise_keypair *keypair);
void noise_keypairs_clear(struct noise_keypairs *keypairs);
bool noise_received_with_keypair(struct noise_keypairs *keypairs, struct noise_keypair *received_keypair);

void noise_set_static_identity_private_key(struct noise_static_identity *static_identity, const u8 private_key[NOISE_PUBLIC_KEY_LEN]);
void noise_set_static_identity_preshared_key(struct noise_static_identity *static_identity, const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

bool noise_handshake_create_initiation(struct message_handshake_initiation *dst, struct noise_handshake *handshake);
struct wireguard_peer *noise_handshake_consume_initiation(struct message_handshake_initiation *src, struct wireguard_device *wg);

bool noise_handshake_create_response(struct message_handshake_response *dst, struct noise_handshake *peer);
struct wireguard_peer *noise_handshake_consume_response(struct message_handshake_response *src, struct wireguard_device *wg);

bool noise_handshake_begin_session(struct noise_handshake *handshake, struct noise_keypairs *keypairs, bool i_am_the_initiator);

#endif
