/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "cookie.h"
#include "peer.h"
#include "device.h"
#include "messages.h"
#include "crypto/blake2s.h"
#include "crypto/chacha20poly1305.h"

#include <linux/jiffies.h>
#include <net/ipv6.h>
#include <crypto/algapi.h>

int cookie_checker_init(struct cookie_checker *checker, struct wireguard_device *wg)
{
	int ret = ratelimiter_init(&checker->ratelimiter, wg);
	if (ret)
		return ret;
	init_rwsem(&checker->secret_lock);
	checker->secret_birthdate = get_jiffies_64();
	get_random_bytes(checker->secret, NOISE_HASH_LEN);
	checker->device = wg;
	return 0;
}

void cookie_checker_uninit(struct cookie_checker *checker)
{
	ratelimiter_uninit(&checker->ratelimiter);
}

void cookie_init(struct cookie *cookie)
{
	memset(cookie, 0, sizeof(struct cookie));
	init_rwsem(&cookie->lock);
}

static void compute_mac1(u8 mac1[COOKIE_LEN], const void *message, size_t len, const u8 pubkey[NOISE_PUBLIC_KEY_LEN], const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	struct blake2s_state state;
	len = len - sizeof(struct message_macs) + offsetof(struct message_macs, mac1);

	if (psk)
		blake2s_init_key(&state, COOKIE_LEN, psk, NOISE_SYMMETRIC_KEY_LEN);
	else
		blake2s_init(&state, COOKIE_LEN);
	blake2s_update(&state, pubkey, NOISE_PUBLIC_KEY_LEN);
	blake2s_update(&state, message, len);
	blake2s_final(&state, mac1, COOKIE_LEN);
}

static void compute_mac2(u8 mac2[COOKIE_LEN], const void *message, size_t len, const u8 cookie[COOKIE_LEN])
{
	len = len - sizeof(struct message_macs) + offsetof(struct message_macs, mac2);
	blake2s(mac2, message, cookie, COOKIE_LEN, len, COOKIE_LEN);
}

static inline const u8 *get_secret(struct cookie_checker *checker)
{
	if (!time_is_after_jiffies64(checker->secret_birthdate + COOKIE_SECRET_MAX_AGE)) {
		down_write(&checker->secret_lock);
		checker->secret_birthdate = get_jiffies_64();
		get_random_bytes(checker->secret, NOISE_HASH_LEN);
		up_write(&checker->secret_lock);
	}
	down_read(&checker->secret_lock);
	return checker->secret;
}

static inline void put_secret(struct cookie_checker *checker)
{
	up_read(&checker->secret_lock);
}

static void make_cookie(u8 cookie[COOKIE_LEN], struct sk_buff *skb, struct cookie_checker *checker)
{
	struct blake2s_state state;
	const u8 *secret;

	secret = get_secret(checker);

	blake2s_init_key(&state, COOKIE_LEN, secret, NOISE_HASH_LEN);
	if (ip_hdr(skb)->version == 4)
		blake2s_update(&state, (u8 *)&ip_hdr(skb)->saddr, sizeof(struct in_addr));
	else if (ip_hdr(skb)->version == 6)
		blake2s_update(&state, (u8 *)&ipv6_hdr(skb)->saddr, sizeof(struct in6_addr));
	blake2s_update(&state, (u8 *)&udp_hdr(skb)->source, sizeof(__be16));
	blake2s_final(&state, cookie, COOKIE_LEN);

	put_secret(checker);
}

enum cookie_mac_state cookie_validate_packet(struct cookie_checker *checker, struct sk_buff *skb, void *data_start, size_t data_len, bool check_cookie)
{
	u8 computed_mac[COOKIE_LEN];
	u8 cookie[COOKIE_LEN];
	enum cookie_mac_state ret;
	struct message_macs *macs = (struct message_macs *)((u8 *)data_start + data_len - sizeof(struct message_macs));

	ret = INVALID_MAC;
	down_read(&checker->device->static_identity.lock);
	if (unlikely(!checker->device->static_identity.has_identity)) {
		up_read(&checker->device->static_identity.lock);
		goto out;
	}
	compute_mac1(computed_mac, data_start, data_len, checker->device->static_identity.static_public, checker->device->static_identity.has_psk ? checker->device->static_identity.preshared_key : NULL);
	up_read(&checker->device->static_identity.lock);
	if (crypto_memneq(computed_mac, macs->mac1, COOKIE_LEN))
		goto out;

	ret = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)
		goto out;

	make_cookie(cookie, skb, checker);

	compute_mac2(computed_mac, data_start, data_len, cookie);
	if (crypto_memneq(computed_mac, macs->mac2, COOKIE_LEN))
		goto out;

	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (!ratelimiter_allow(&checker->ratelimiter, skb))
		goto out;

	ret = VALID_MAC_WITH_COOKIE;

out:
	memzero_explicit(computed_mac, COOKIE_LEN);
	memzero_explicit(cookie, COOKIE_LEN);
	return ret;
}

void cookie_add_mac_to_packet(void *message, size_t len, struct wireguard_peer *peer)
{
	struct message_macs *macs = (struct message_macs *)((u8 *)message + len - sizeof(struct message_macs));

	down_read(&peer->device->static_identity.lock);
	if (unlikely(!peer->device->static_identity.has_identity)) {
		memset(macs, 0, sizeof(struct message_macs));
		up_read(&peer->device->static_identity.lock);
		return;
	}
	compute_mac1(macs->mac1, message, len, peer->handshake.remote_static, peer->device->static_identity.has_psk ? peer->device->static_identity.preshared_key : NULL);
	up_read(&peer->device->static_identity.lock);

	down_write(&peer->latest_cookie.lock);
	memcpy(peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
	peer->latest_cookie.have_sent_mac1 = true;
	up_write(&peer->latest_cookie.lock);

	down_read(&peer->latest_cookie.lock);
	if (peer->latest_cookie.is_valid && time_is_after_jiffies64(peer->latest_cookie.birthdate + COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
		compute_mac2(macs->mac2, message, len, peer->latest_cookie.cookie);
	else
		memset(macs->mac2, 0, COOKIE_LEN);
	up_read(&peer->latest_cookie.lock);
}

void cookie_message_create(struct message_handshake_cookie *dst, struct sk_buff *skb, void *data_start, size_t data_len, __le32 index, struct cookie_checker *checker)
{
	struct message_macs *macs = (struct message_macs *)((u8 *)data_start + data_len - sizeof(struct message_macs));
	struct blake2s_state state;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 cookie[COOKIE_LEN];

	dst->header.type = MESSAGE_HANDSHAKE_COOKIE;
	dst->receiver_index = index;
	get_random_bytes(dst->salt, COOKIE_SALT_LEN);
	blake2s(dst->salt, dst->salt, NULL, COOKIE_SALT_LEN, COOKIE_SALT_LEN, 0); /* Avoid directly transmitting RNG output. */

	down_read(&checker->device->static_identity.lock);
	if (unlikely(!checker->device->static_identity.has_identity)) {
		memset(dst, 0, sizeof(struct message_handshake_cookie));
		up_read(&checker->device->static_identity.lock);
		return;
	}
	if (checker->device->static_identity.has_psk)
		blake2s_init_key(&state, NOISE_SYMMETRIC_KEY_LEN, checker->device->static_identity.preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	else
		blake2s_init(&state, NOISE_SYMMETRIC_KEY_LEN);
	blake2s_update(&state, checker->device->static_identity.static_public, NOISE_PUBLIC_KEY_LEN);
	up_read(&checker->device->static_identity.lock);
	blake2s_update(&state, dst->salt, COOKIE_SALT_LEN);
	blake2s_final(&state, key, NOISE_SYMMETRIC_KEY_LEN);

	make_cookie(cookie, skb, checker);
	chacha20poly1305_encrypt(dst->encrypted_cookie, cookie, COOKIE_LEN, macs->mac1, COOKIE_LEN, 0, key);

	memzero_explicit(key, NOISE_HASH_LEN);
	memzero_explicit(cookie, COOKIE_LEN);
}

void cookie_message_consume(struct message_handshake_cookie *src, struct wireguard_device *wg)
{
	struct blake2s_state state;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 cookie[COOKIE_LEN];
	struct index_hashtable_entry *entry;

	entry = index_hashtable_lookup(&wg->index_hashtable, INDEX_HASHTABLE_HANDSHAKE | INDEX_HASHTABLE_KEYPAIR, src->receiver_index);
	if (!unlikely(entry))
		return;

	down_read(&entry->peer->latest_cookie.lock);
	if (unlikely(!entry->peer->latest_cookie.have_sent_mac1)) {
		up_read(&entry->peer->latest_cookie.lock);
		goto out;
	}
	up_read(&entry->peer->latest_cookie.lock);

	down_read(&wg->static_identity.lock);
	if (unlikely(!wg->static_identity.has_identity)) {
		up_read(&wg->static_identity.lock);
		goto out;
	}
	if (wg->static_identity.has_psk)
		blake2s_init_key(&state, NOISE_SYMMETRIC_KEY_LEN, wg->static_identity.preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	else
		blake2s_init(&state, NOISE_SYMMETRIC_KEY_LEN);
	up_read(&wg->static_identity.lock);

	blake2s_update(&state, entry->peer->handshake.remote_static, NOISE_PUBLIC_KEY_LEN);
	blake2s_update(&state, src->salt, COOKIE_SALT_LEN);
	blake2s_final(&state, key, NOISE_SYMMETRIC_KEY_LEN);

	down_write(&entry->peer->latest_cookie.lock);
	if (chacha20poly1305_decrypt(cookie, src->encrypted_cookie, sizeof(src->encrypted_cookie), entry->peer->latest_cookie.last_mac1_sent, COOKIE_LEN, 0, key)) {
		memcpy(entry->peer->latest_cookie.cookie, cookie, COOKIE_LEN);
		entry->peer->latest_cookie.birthdate = get_jiffies_64();
		entry->peer->latest_cookie.is_valid = true;
		entry->peer->latest_cookie.have_sent_mac1 = false;
	} else
		net_dbg_ratelimited("Could not decrypt invalid cookie response\n");
	up_write(&entry->peer->latest_cookie.lock);

out:
	peer_put(entry->peer);
	memzero_explicit(key, NOISE_HASH_LEN);
	memzero_explicit(cookie, COOKIE_LEN);
}
