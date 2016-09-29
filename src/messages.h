/*
 * Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * See doc/protocol.md for more info
 */

#ifndef MESSAGES_H
#define MESSAGES_H

#include "crypto/curve25519.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/blake2s.h"

#include <linux/kernel.h>
#include <linux/param.h>

enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_POINT_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEYLEN,
	NOISE_TIMESTAMP_LEN = sizeof(u64) + sizeof(u32),
	NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAGLEN,
	NOISE_HASH_LEN = BLAKE2S_OUTBYTES
};

#define noise_encrypted_len(plain_len) (plain_len + NOISE_AUTHTAG_LEN)

enum cookie_values {
	COOKIE_SECRET_MAX_AGE = 2 * 60 * HZ,
	COOKIE_SECRET_LATENCY = 5 * HZ,
	COOKIE_SALT_LEN = 32,
	COOKIE_LEN = 16
};

enum counter_values {
	COUNTER_BITS_TOTAL = 2048,
	COUNTER_REDUNDANT_BITS = BITS_PER_LONG,
	COUNTER_WINDOW_SIZE = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS
};

enum limits {
	REKEY_AFTER_MESSAGES = U64_MAX - 0xffff,
	REJECT_AFTER_MESSAGES = U64_MAX - COUNTER_WINDOW_SIZE - 1,
	REKEY_TIMEOUT = 5 * HZ,
	REKEY_AFTER_TIME = 120 * HZ,
	REJECT_AFTER_TIME = 180 * HZ,
	INITIATIONS_PER_SECOND = HZ / 50,
	MAX_PEERS_PER_DEVICE = U16_MAX
};

enum message_type {
	MESSAGE_INVALID = 0,
	MESSAGE_HANDSHAKE_INITIATION = 1,
	MESSAGE_HANDSHAKE_RESPONSE = 2,
	MESSAGE_HANDSHAKE_COOKIE = 3,
	MESSAGE_DATA = 4,
	MESSAGE_TOTAL = 5
};

struct message_header {
	u8 type;
} __packed;

struct message_macs {
	u8 mac1[COOKIE_LEN];
	u8 mac2[COOKIE_LEN];
} __packed;

struct message_handshake_initiation {
	struct message_header header;
	__le32 sender_index;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_static[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
	u8 encrypted_timestamp[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
	struct message_macs macs;
} __packed;

struct message_handshake_response {
	struct message_header header;
	__le32 sender_index;
	__le32 receiver_index;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_nothing[noise_encrypted_len(0)];
	struct message_macs macs;
} __packed;

struct message_handshake_cookie {
	struct message_header header;
	__le32 receiver_index;
	u8 salt[COOKIE_SALT_LEN];
	u8 encrypted_cookie[noise_encrypted_len(COOKIE_LEN)];
} __packed;

struct message_data {
	struct message_header header;
	__le32 key_idx;
	__le64 counter;
	u8 encrypted_data[];
} __packed;

#define message_data_len(plain_len) (noise_encrypted_len(plain_len) + sizeof(struct message_data))

enum message_alignments {
	MESSAGE_DATA_TARGET_OFFSET = sizeof(struct message_data),
	MESSAGE_DATA_TARGET_OPTIMAL_ALIGNMENT = 32, /* Per intel AVX recommendations */
	MESSAGE_PADDING_MULTIPLE = 16,
	MESSAGE_MINIMUM_LENGTH = message_data_len(0)
};

static inline enum message_type message_determine_type(void *src, size_t src_len)
{
	struct message_header *header = src;
	if (unlikely(src_len < sizeof(struct message_header)))
		return MESSAGE_INVALID;
	if (header->type == MESSAGE_DATA && src_len >= MESSAGE_MINIMUM_LENGTH)
		return MESSAGE_DATA;
	if (header->type == MESSAGE_HANDSHAKE_INITIATION && src_len == sizeof(struct message_handshake_initiation))
		return MESSAGE_HANDSHAKE_INITIATION;
	if (header->type == MESSAGE_HANDSHAKE_RESPONSE && src_len == sizeof(struct message_handshake_response))
		return MESSAGE_HANDSHAKE_RESPONSE;
	if (header->type == MESSAGE_HANDSHAKE_COOKIE && src_len == sizeof(struct message_handshake_cookie))
		return MESSAGE_HANDSHAKE_COOKIE;
	return MESSAGE_INVALID;
}

#endif
