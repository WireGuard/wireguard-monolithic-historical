/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "allowedips.h"
#include "peer.h"

struct allowedips_node {
	struct wireguard_peer *peer;
	struct rcu_head rcu;
	struct allowedips_node __rcu *bit[2];
	/* While it may seem scandalous that we waste space for v4,
	 * we're alloc'ing to the nearest power of 2 anyway, so this
	 * doesn't actually make a difference.
	 */
	u8 bits[16] __aligned(__alignof(u64));
	u8 cidr, bit_at_a, bit_at_b;
};

static __always_inline void swap_endian(u8 *dst, const u8 *src, u8 bits)
{
	if (bits == 32)
		*(u32 *)dst = be32_to_cpu(*(const __be32 *)src);
	else if (bits == 128) {
		((u64 *)dst)[0] = be64_to_cpu(((const __be64 *)src)[0]);
		((u64 *)dst)[1] = be64_to_cpu(((const __be64 *)src)[1]);
	}
}

static void copy_and_assign_cidr(struct allowedips_node *node, const u8 *src, u8 cidr, u8 bits)
{
	node->cidr = cidr;
	node->bit_at_a = cidr / 8U;
#ifdef __LITTLE_ENDIAN
	node->bit_at_a ^= (bits / 8U - 1U) % 8U;
#endif
	node->bit_at_b = 7U - (cidr % 8U);
	memcpy(node->bits, src, bits / 8U);
}

#define choose_node(parent, key) parent->bit[(key[parent->bit_at_a] >> parent->bit_at_b) & 1]

static void node_free_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct allowedips_node, rcu));
}

#define push(stack, p, len) ({ \
	if (rcu_access_pointer(p)) { \
		BUG_ON(len >= 128); \
		stack[len++] = rcu_dereference_protected(p, lockdep_is_held(lock)); \
	} \
	true; \
})
static void free_root_node(struct allowedips_node __rcu *top, struct mutex *lock)
{
	struct allowedips_node *stack[128], *node;
	unsigned int len;

	for (len = 0, push(stack, top, len); len > 0 && (node = stack[--len]) && push(stack, node->bit[0], len) && push(stack, node->bit[1], len);)
		call_rcu_bh(&node->rcu, node_free_rcu);
}

static int walk_by_peer(struct allowedips_node __rcu *top, u8 bits, struct allowedips_cursor *cursor, struct wireguard_peer *peer, int (*func)(void *ctx, const u8 *ip, u8 cidr, int family), void *ctx, struct mutex *lock)
{
	struct allowedips_node *node;
	int ret;
	u8 ip[16] __aligned(__alignof(u64));

	if (!rcu_access_pointer(top))
		return 0;

	if (!cursor->len)
		push(cursor->stack, top, cursor->len);

	for (; cursor->len > 0 && (node = cursor->stack[cursor->len - 1]); --cursor->len, push(cursor->stack, node->bit[0], cursor->len), push(cursor->stack, node->bit[1], cursor->len)) {
		if (node->peer != peer)
			continue;

		swap_endian(ip, node->bits, bits);
		memset(ip + (node->cidr + 7U) / 8U, 0, (bits / 8U) - ((node->cidr + 7U) / 8U));
		if (node->cidr)
			ip[(node->cidr + 7U) / 8U - 1U] &= ~0U << (-node->cidr % 8U);

		ret = func(ctx, ip, node->cidr, bits == 32 ? AF_INET : AF_INET6);
		if (ret)
			return ret;
	}
	return 0;
}
#undef push

#define ref(p) rcu_access_pointer(p)
#define deref(p) rcu_dereference_protected(*p, lockdep_is_held(lock))
#define push(p) ({ BUG_ON(len >= 128); stack[len++] = p; })
static void walk_remove_by_peer(struct allowedips_node __rcu **top, struct wireguard_peer *peer, struct mutex *lock)
{
	struct allowedips_node __rcu **stack[128], **nptr;
	struct allowedips_node *node, *prev;
	unsigned int len;

	if (unlikely(!peer || !ref(*top)))
		return;

	for (prev = NULL, len = 0, push(top); len > 0; prev = node) {
		nptr = stack[len - 1];
		node = deref(nptr);
		if (!node) {
			--len;
			continue;
		}
		if (!prev || ref(prev->bit[0]) == node || ref(prev->bit[1]) == node) {
			if (ref(node->bit[0]))
				push(&node->bit[0]);
			else if (ref(node->bit[1]))
				push(&node->bit[1]);
		} else if (ref(node->bit[0]) == prev) {
			if (ref(node->bit[1]))
				push(&node->bit[1]);
		} else {
			if (node->peer == peer) {
				node->peer = NULL;
				if (!node->bit[0] || !node->bit[1]) {
					rcu_assign_pointer(*nptr, deref(&node->bit[!ref(node->bit[0])]));
					call_rcu_bh(&node->rcu, node_free_rcu);
					node = deref(nptr);
				}
			}
			--len;
		}
	}
}
#undef ref
#undef deref
#undef push

static __always_inline unsigned int fls128(u64 a, u64 b)
{
	return a ? fls64(a) + 64U : fls64(b);
}

static __always_inline u8 common_bits(const struct allowedips_node *node, const u8 *key, u8 bits)
{
	if (bits == 32)
		return 32U - fls(*(const u32 *)node->bits ^ *(const u32 *)key);
	else if (bits == 128)
		return 128U - fls128(*(const u64 *)&node->bits[0] ^ *(const u64 *)&key[0], *(const u64 *)&node->bits[8] ^ *(const u64 *)&key[8]);
	return 0;
}

/* This could be much faster if it actually just compared the common bits properly,
 * by precomputing a mask bswap(~0 << (32 - cidr)), and the rest, but it turns out that
 * common_bits is already super fast on modern processors, even taking into account
 * the unfortunate bswap. So, we just inline it like this instead.
 */
#define prefix_matches(node, key, bits) (common_bits(node, key, bits) >= node->cidr)

static __always_inline struct allowedips_node *find_node(struct allowedips_node *trie, u8 bits, const u8 *key)
{
	struct allowedips_node *node = trie, *found = NULL;

	while (node && prefix_matches(node, key, bits)) {
		if (node->peer)
			found = node;
		if (node->cidr == bits)
			break;
		node = rcu_dereference_bh(choose_node(node, key));
	}
	return found;
}

/* Returns a strong reference to a peer */
static __always_inline struct wireguard_peer *lookup(struct allowedips_node __rcu *root, u8 bits, const void *be_ip)
{
	struct wireguard_peer *peer = NULL;
	struct allowedips_node *node;
	u8 ip[16] __aligned(__alignof(u64));

	swap_endian(ip, be_ip, bits);

	rcu_read_lock_bh();
	node = find_node(rcu_dereference_bh(root), bits, ip);
	if (node)
		peer = peer_get(node->peer);
	rcu_read_unlock_bh();
	return peer;
}

__attribute__((nonnull(1)))
static inline bool node_placement(struct allowedips_node __rcu *trie, const u8 *key, u8 cidr, u8 bits, struct allowedips_node **rnode, struct mutex *lock)
{
	bool exact = false;
	struct allowedips_node *parent = NULL, *node = rcu_dereference_protected(trie, lockdep_is_held(lock));

	while (node && node->cidr <= cidr && prefix_matches(node, key, bits)) {
		parent = node;
		if (parent->cidr == cidr) {
			exact = true;
			break;
		}
		node = rcu_dereference_protected(choose_node(parent, key), lockdep_is_held(lock));
	}
	*rnode = parent;
	return exact;
}

static int add(struct allowedips_node __rcu **trie, u8 bits, const u8 *be_key, u8 cidr, struct wireguard_peer *peer, struct mutex *lock)
{
	struct allowedips_node *node, *parent, *down, *newnode;
	u8 key[16] __aligned(__alignof(u64));

	if (unlikely(cidr > bits || !peer))
		return -EINVAL;

	swap_endian(key, be_key, bits);

	if (!rcu_access_pointer(*trie)) {
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		if (!node)
			return -ENOMEM;
		node->peer = peer;
		copy_and_assign_cidr(node, key, cidr, bits);
		rcu_assign_pointer(*trie, node);
		return 0;
	}
	if (node_placement(*trie, key, cidr, bits, &node, lock)) {
		node->peer = peer;
		return 0;
	}

	newnode = kzalloc(sizeof(*newnode), GFP_KERNEL);
	if (!newnode)
		return -ENOMEM;
	newnode->peer = peer;
	copy_and_assign_cidr(newnode, key, cidr, bits);

	if (!node)
		down = rcu_dereference_protected(*trie, lockdep_is_held(lock));
	else {
		down = rcu_dereference_protected(choose_node(node, key), lockdep_is_held(lock));
		if (!down) {
			rcu_assign_pointer(choose_node(node, key), newnode);
			return 0;
		}
	}
	cidr = min(cidr, common_bits(down, key, bits));
	parent = node;

	if (newnode->cidr == cidr) {
		rcu_assign_pointer(choose_node(newnode, down->bits), down);
		if (!parent)
			rcu_assign_pointer(*trie, newnode);
		else
			rcu_assign_pointer(choose_node(parent, newnode->bits), newnode);
	} else {
		node = kzalloc(sizeof(*node), GFP_KERNEL);
		if (!node) {
			kfree(newnode);
			return -ENOMEM;
		}
		copy_and_assign_cidr(node, newnode->bits, cidr, bits);

		rcu_assign_pointer(choose_node(node, down->bits), down);
		rcu_assign_pointer(choose_node(node, newnode->bits), newnode);
		if (!parent)
			rcu_assign_pointer(*trie, node);
		else
			rcu_assign_pointer(choose_node(parent, node->bits), node);
	}
	return 0;
}

void allowedips_init(struct allowedips *table)
{
	table->root4 = table->root6 = NULL;
	table->seq = 1;
}

void allowedips_free(struct allowedips *table, struct mutex *lock)
{
	struct allowedips_node __rcu *old4 = table->root4, *old6 = table->root6;
	++table->seq;
	rcu_assign_pointer(table->root4, NULL);
	rcu_assign_pointer(table->root6, NULL);
	free_root_node(old4, lock);
	free_root_node(old6, lock);
}

int allowedips_insert_v4(struct allowedips *table, const struct in_addr *ip, u8 cidr, struct wireguard_peer *peer, struct mutex *lock)
{
	++table->seq;
	return add(&table->root4, 32, (const u8 *)ip, cidr, peer, lock);
}

int allowedips_insert_v6(struct allowedips *table, const struct in6_addr *ip, u8 cidr, struct wireguard_peer *peer, struct mutex *lock)
{
	++table->seq;
	return add(&table->root6, 128, (const u8 *)ip, cidr, peer, lock);
}

void allowedips_remove_by_peer(struct allowedips *table, struct wireguard_peer *peer, struct mutex *lock)
{
	++table->seq;
	walk_remove_by_peer(&table->root4, peer, lock);
	walk_remove_by_peer(&table->root6, peer, lock);
}

int allowedips_walk_by_peer(struct allowedips *table, struct allowedips_cursor *cursor, struct wireguard_peer *peer, int (*func)(void *ctx, const u8 *ip, u8 cidr, int family), void *ctx, struct mutex *lock)
{
	int ret;

	if (!cursor->seq)
		cursor->seq = table->seq;
	else if (cursor->seq != table->seq)
		return 0;

	if (!cursor->second_half) {
		ret = walk_by_peer(table->root4, 32, cursor, peer, func, ctx, lock);
		if (ret)
			return ret;
		cursor->len = 0;
		cursor->second_half = true;
	}
	return walk_by_peer(table->root6, 128, cursor, peer, func, ctx, lock);
}

/* Returns a strong reference to a peer */
struct wireguard_peer *allowedips_lookup_dst(struct allowedips *table, struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		return lookup(table->root4, 32, &ip_hdr(skb)->daddr);
	else if (skb->protocol == htons(ETH_P_IPV6))
		return lookup(table->root6, 128, &ipv6_hdr(skb)->daddr);
	return NULL;
}

/* Returns a strong reference to a peer */
struct wireguard_peer *allowedips_lookup_src(struct allowedips *table, struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		return lookup(table->root4, 32, &ip_hdr(skb)->saddr);
	else if (skb->protocol == htons(ETH_P_IPV6))
		return lookup(table->root6, 128, &ipv6_hdr(skb)->saddr);
	return NULL;
}

#include "selftest/allowedips.h"
