/*
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
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
#include <linux/skbuff.h>

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
	COOKIE_NONCE_LEN = XCHACHA20POLY1305_NONCELEN,
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
	REKEY_TIMEOUT_JITTER_MAX = HZ / 3,
	REKEY_AFTER_TIME = 120 * HZ,
	REJECT_AFTER_TIME = 180 * HZ,
	INITIATIONS_PER_SECOND = HZ / 50,
	MAX_PEERS_PER_DEVICE = U16_MAX,
	KEEPALIVE_TIMEOUT = 10 * HZ,
	MAX_TIMER_HANDSHAKES = (90 * HZ) / REKEY_TIMEOUT,
	MAX_QUEUED_INCOMING_HANDSHAKES = 4096,
	MAX_QUEUED_OUTGOING_PACKETS = 1024
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
	/* The actual layout of this that we want is:
	 * u8 type
	 * u8 reserved_zero[3]
	 *
	 * But it turns out that by encoding this as little endian,
	 * we achieve the same thing, and it makes checking faster.
	 */
	__le32 type;
};

struct message_macs {
	u8 mac1[COOKIE_LEN];
	u8 mac2[COOKIE_LEN];
};

struct message_handshake_initiation {
	struct message_header header;
	__le32 sender_index;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_static[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
	u8 encrypted_timestamp[noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
	struct message_macs macs;
};

struct message_handshake_response {
	struct message_header header;
	__le32 sender_index;
	__le32 receiver_index;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_nothing[noise_encrypted_len(0)];
	struct message_macs macs;
};

struct message_handshake_cookie {
	struct message_header header;
	__le32 receiver_index;
	u8 nonce[COOKIE_NONCE_LEN];
	u8 encrypted_cookie[noise_encrypted_len(COOKIE_LEN)];
};

struct message_data {
	struct message_header header;
	__le32 key_idx;
	__le64 counter;
	u8 encrypted_data[];
};

#define message_data_len(plain_len) (noise_encrypted_len(plain_len) + sizeof(struct message_data))

enum message_alignments {
	MESSAGE_PADDING_MULTIPLE = 16,
	MESSAGE_MINIMUM_LENGTH = message_data_len(0)
};

#define SKB_HEADER_LEN (max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) + sizeof(struct udphdr) + NET_SKB_PAD)
#define DATA_PACKET_HEAD_ROOM ALIGN(sizeof(struct message_data) + SKB_HEADER_LEN, 4)

enum {
	HANDSHAKE_DSCP = 0b10001000 /* AF41, plus 00 ECN */
};

static const unsigned int message_header_sizes[MESSAGE_TOTAL] = {
	[MESSAGE_HANDSHAKE_INITIATION] = sizeof(struct message_handshake_initiation),
	[MESSAGE_HANDSHAKE_RESPONSE] = sizeof(struct message_handshake_response),
	[MESSAGE_HANDSHAKE_COOKIE] = sizeof(struct message_handshake_cookie),
	[MESSAGE_DATA] = sizeof(struct message_data)
};

static inline enum message_type message_determine_type(struct sk_buff *skb)
{
	struct message_header *header = (struct message_header *)skb->data;
	if (unlikely(skb->len < sizeof(struct message_header)))
		return MESSAGE_INVALID;
	if (header->type == cpu_to_le32(MESSAGE_DATA) && skb->len >= MESSAGE_MINIMUM_LENGTH)
		return MESSAGE_DATA;
	if (header->type == cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION) && skb->len == sizeof(struct message_handshake_initiation))
		return MESSAGE_HANDSHAKE_INITIATION;
	if (header->type == cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE) && skb->len == sizeof(struct message_handshake_response))
		return MESSAGE_HANDSHAKE_RESPONSE;
	if (header->type == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE) && skb->len == sizeof(struct message_handshake_cookie))
		return MESSAGE_HANDSHAKE_COOKIE;
	return MESSAGE_INVALID;
}

#endif
