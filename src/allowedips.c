/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "allowedips.h"
#include "peer.h"

struct allowedips_node {
	struct allowedips_node __rcu *bit[2];
	/* While it may seem scandalous that we waste space for v4,
	 * we're alloc'ing to the nearest power of 2 anyway, so this
	 * doesn't actually make a difference.
	 */
	union {
		__be64 v6[2];
		__be32 v4;
		u8 bits[16];
	};
	union {
		__be64 mask_v6;
		__be32 mask_v4;
	};
	u8 cidr, bit_at_a, bit_at_b;
	/* Putting these members here puts a big hole in the struct,
	 * but it also keeps it above the cache line, which is important.
	 */
	struct wireguard_peer *peer;
	struct rcu_head rcu;
};

static void copy_and_assign_cidr(struct allowedips_node *node, const u8 *src, u8 cidr, u8 bits)
{
	node->cidr = cidr;
	node->bit_at_a = cidr / 8;
	node->bit_at_b = 7 - (cidr % 8);
	if (cidr) {
		memcpy(node->bits, src, (cidr + 7) / 8);
		node->bits[(cidr + 7) / 8 - 1] &= ~0U << ((8 - (cidr % 8)) % 8);
		if (bits == 32)
			node->mask_v4 = cpu_to_be32(~0U << (32 - cidr));
		else if (bits == 128)
			node->mask_v6 = cpu_to_be64(~0ULL << (64 - (cidr & 63)));
	}
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

static int walk_by_peer(struct allowedips_node __rcu *top, int family, struct allowedips_cursor *cursor, struct wireguard_peer *peer, int (*func)(void *ctx, const u8 *ip, u8 cidr, int family), void *ctx, struct mutex *lock)
{
	struct allowedips_node *node;
	int ret;

	if (!rcu_access_pointer(top))
		return 0;

	if (!cursor->len)
		push(cursor->stack, top, cursor->len);

	for (; cursor->len > 0 && (node = cursor->stack[cursor->len - 1]); --cursor->len, push(cursor->stack, node->bit[0], cursor->len), push(cursor->stack, node->bit[1], cursor->len)) {
		if (node->peer != peer)
			continue;
		ret = func(ctx, node->bits, node->cidr, family);
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
	return a ? fls64(a) + 64 : fls64(b);
}

static __always_inline u8 common_bits(const struct allowedips_node *node, const u8 *key, u8 bits)
{
	if (bits == 32)
		return 32 - fls(be32_to_cpu(*(const __be32 *)node->bits ^ *(const __be32 *)key));
	else if (bits == 128)
		return 128 - fls128(be64_to_cpu(*(const __be64 *)&node->bits[0] ^ *(const __be64 *)&key[0]), be64_to_cpu(*(const __be64 *)&node->bits[8] ^ *(const __be64 *)&key[8]));
	return 0;
}
static __always_inline bool prefix_matches(struct allowedips_node *node, const u8 *key, u8 bits)
{
	if (!node->cidr)
		return true;
	if (bits == 32)
		return !((node->v4 ^ ((__be32 *)key)[0]) & node->mask_v4);
	else if (bits == 128) {
		if (node->cidr >= 64) {
			if (node->v6[0] ^ ((__be64 *)key)[0])
				return false;
			if (node->cidr == 64)
				return true;
			return !((node->v6[1] ^ ((__be64 *)key)[1]) & node->mask_v6);
		}
		return !((node->v6[0] ^ ((__be64 *)key)[0]) & node->mask_v6);
	} else
		return false;
}

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
static __always_inline struct wireguard_peer *lookup(struct allowedips_node __rcu *root, u8 bits, const void *ip)
{
	struct wireguard_peer *peer = NULL;
	struct allowedips_node *node;

	rcu_read_lock_bh();
	node = find_node(rcu_dereference_bh(root), bits, ip);
	if (node)
		peer = peer_get(node->peer);
	rcu_read_unlock_bh();
	return peer;
}

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

static int add(struct allowedips_node __rcu **trie, u8 bits, const u8 *key, u8 cidr, struct wireguard_peer *peer, struct mutex *lock)
{
	struct allowedips_node *node, *parent, *down, *newnode;

	if (unlikely(cidr > bits || !peer))
		return -EINVAL;

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
	++table->seq;
	free_root_node(table->root4, lock);
	rcu_assign_pointer(table->root4, NULL);
	free_root_node(table->root6, lock);
	rcu_assign_pointer(table->root6, NULL);
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
		ret = walk_by_peer(table->root4, AF_INET, cursor, peer, func, ctx, lock);
		if (ret)
			return ret;
		cursor->len = 0;
		cursor->second_half = true;
	}
	return walk_by_peer(table->root6, AF_INET6, cursor, peer, func, ctx, lock);
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
