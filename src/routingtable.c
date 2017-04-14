/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "routingtable.h"
#include "peer.h"

struct routing_table_node {
	struct routing_table_node __rcu *bit[2];
	struct rcu_head rcu;
	struct wireguard_peer *peer;
	u8 cidr, bit_at_a, bit_at_b;
	u8 bits[] __aligned(__alignof__(u64));
};

static inline void copy_and_assign_cidr(struct routing_table_node *node, const u8 *src, u8 cidr)
{
	memcpy(node->bits, src, (cidr + 7) / 8);
	node->bits[(cidr + 7) / 8 - 1] &= 0xff << ((8 - (cidr % 8)) % 8);
	node->cidr = cidr;
	node->bit_at_a = cidr / 8;
	node->bit_at_b = 7 - (cidr % 8);
}
#define choose_node(parent, key) parent->bit[(key[parent->bit_at_a] >> parent->bit_at_b) & 1]

static void node_free_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct routing_table_node, rcu));
}
#define push(p, lock) ({ \
	if (rcu_access_pointer(p)) { \
		BUG_ON(len >= 128); \
		stack[len++] = lock ? rcu_dereference_protected(p, lockdep_is_held((struct mutex *)lock)) : rcu_dereference_bh(p); \
	} \
	true; \
})
#define walk_prep \
	struct routing_table_node *stack[128], *node; \
	unsigned int len;
#define walk(top, lock) for (len = 0, push(top, lock); len > 0 && (node = stack[--len]) && push(node->bit[0], lock) && push(node->bit[1], lock);)

static void free_root_node(struct routing_table_node __rcu *top, struct mutex *lock)
{
	walk_prep;
	walk (top, lock)
		call_rcu_bh(&node->rcu, node_free_rcu);
}

static size_t count_nodes(struct routing_table_node __rcu *top)
{
	size_t ret = 0;
	walk_prep;
	walk (top, NULL) {
		if (node->peer)
			++ret;
	}
	return ret;
}

static int walk_ips_by_peer(struct routing_table_node __rcu *top, int family, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, u8 cidr, int family), struct mutex *maybe_lock)
{
	int ret;
	union nf_inet_addr ip = { .all = { 0 } };
	walk_prep;

	if (unlikely(!peer))
		return 0;

	walk (top, maybe_lock) {
		if (node->peer != peer)
			continue;
		memcpy(ip.all, node->bits, family == AF_INET6 ? 16 : 4);
		ret = func(ctx, ip, node->cidr, family);
		if (ret)
			return ret;
	}
	return 0;
}
#undef push

#define ref(p) rcu_access_pointer(p)
#define deref(p) rcu_dereference_protected(*p, lockdep_is_held(lock))
#define push(p) ({ BUG_ON(len >= 128); stack[len++] = p; })
static void walk_remove_by_peer(struct routing_table_node __rcu **top, struct wireguard_peer *peer, struct mutex *lock)
{
	struct routing_table_node __rcu **stack[128], **nptr, *node, *prev;
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

static inline unsigned int fls128(u64 a, u64 b)
{
	return a ? fls64(a) + 64 : fls64(b);
}

static inline u8 common_bits(const struct routing_table_node *node, const u8 *key, u8 bits)
{
	if (bits == 32)
		return 32 - fls(be32_to_cpu(*(const __be32 *)node->bits ^ *(const __be32 *)key));
	else if (bits == 128)
		return 128 - fls128(be64_to_cpu(*(const __be64 *)&node->bits[0] ^ *(const __be64 *)&key[0]), be64_to_cpu(*(const __be64 *)&node->bits[8] ^ *(const __be64 *)&key[8]));
	BUG();
	return 0;
}

static inline struct routing_table_node *find_node(struct routing_table_node *trie, u8 bits, const u8 *key)
{
	struct routing_table_node *node = trie, *found = NULL;

	while (node && common_bits(node, key, bits) >= node->cidr) {
		if (node->peer)
			found = node;
		if (node->cidr == bits)
			break;
		node = rcu_dereference_bh(choose_node(node, key));
	}
	return found;
}

/* Returns a strong reference to a peer */
static inline struct wireguard_peer *lookup(struct routing_table_node __rcu *root, u8 bits, const void *ip)
{
	struct wireguard_peer *peer = NULL;
	struct routing_table_node *node;

	rcu_read_lock_bh();
	node = find_node(rcu_dereference_bh(root), bits, ip);
	if (node)
		peer = peer_get(node->peer);
	rcu_read_unlock_bh();
	return peer;
}

static inline bool node_placement(struct routing_table_node __rcu *trie, const u8 *key, u8 cidr, u8 bits, struct routing_table_node **rnode, struct mutex *lock)
{
	bool exact = false;
	struct routing_table_node *parent = NULL, *node = rcu_dereference_protected(trie, lockdep_is_held(lock));

	while (node && node->cidr <= cidr && common_bits(node, key, bits) >= node->cidr) {
		parent = node;
		if (parent->cidr == cidr) {
			exact = true;
			break;
		}
		node = rcu_dereference_protected(choose_node(parent, key), lockdep_is_held(lock));
	}
	if (rnode)
		*rnode = parent;
	return exact;
}

static int add(struct routing_table_node __rcu **trie, u8 bits, const u8 *key, u8 cidr, struct wireguard_peer *peer, struct mutex *lock)
{
	struct routing_table_node *node, *parent, *down, *newnode;

	if (!rcu_access_pointer(*trie)) {
		node = kzalloc(sizeof(*node) + (bits + 7) / 8, GFP_KERNEL);
		if (!node)
			return -ENOMEM;
		node->peer = peer;
		copy_and_assign_cidr(node, key, cidr);
		rcu_assign_pointer(*trie, node);
		return 0;
	}
	if (node_placement(*trie, key, cidr, bits, &node, lock)) {
		node->peer = peer;
		return 0;
	}

	newnode = kzalloc(sizeof(*node) + (bits + 7) / 8, GFP_KERNEL);
	if (!newnode)
		return -ENOMEM;
	newnode->peer = peer;
	copy_and_assign_cidr(newnode, key, cidr);

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
		node = kzalloc(sizeof(*node) + (bits + 7) / 8, GFP_KERNEL);
		if (!node) {
			kfree(newnode);
			return -ENOMEM;
		}
		copy_and_assign_cidr(node, newnode->bits, cidr);

		rcu_assign_pointer(choose_node(node, down->bits), down);
		rcu_assign_pointer(choose_node(node, newnode->bits), newnode);
		if (!parent)
			rcu_assign_pointer(*trie, node);
		else
			rcu_assign_pointer(choose_node(parent, node->bits), node);
	}
	return 0;
}

void routing_table_init(struct routing_table *table)
{
	memset(table, 0, sizeof(struct routing_table));
	mutex_init(&table->table_update_lock);
}

void routing_table_free(struct routing_table *table)
{
	mutex_lock(&table->table_update_lock);
	free_root_node(table->root4, &table->table_update_lock);
	rcu_assign_pointer(table->root4, NULL);
	free_root_node(table->root6, &table->table_update_lock);
	rcu_assign_pointer(table->root6, NULL);
	mutex_unlock(&table->table_update_lock);
}

int routing_table_insert_v4(struct routing_table *table, const struct in_addr *ip, u8 cidr, struct wireguard_peer *peer)
{
	int ret;
	if (unlikely(cidr > 32 || !peer))
		return -EINVAL;
	mutex_lock(&table->table_update_lock);
	ret = add(&table->root4, 32, (const u8 *)ip, cidr, peer, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return ret;
}

int routing_table_insert_v6(struct routing_table *table, const struct in6_addr *ip, u8 cidr, struct wireguard_peer *peer)
{
	int ret;
	if (unlikely(cidr > 128 || !peer))
		return -EINVAL;
	mutex_lock(&table->table_update_lock);
	ret = add(&table->root6, 128, (const u8 *)ip, cidr, peer, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return ret;
}

void routing_table_remove_by_peer(struct routing_table *table, struct wireguard_peer *peer)
{
	mutex_lock(&table->table_update_lock);
	walk_remove_by_peer(&table->root4, peer, &table->table_update_lock);
	walk_remove_by_peer(&table->root6, peer, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
}

size_t routing_table_count_nodes(struct routing_table *table)
{
	size_t ret;
	rcu_read_lock_bh();
	ret = count_nodes(table->root4) + count_nodes(table->root6);
	rcu_read_unlock_bh();
	return ret;
}

int routing_table_walk_ips_by_peer(struct routing_table *table, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, u8 cidr, int family))
{
	int ret;
	rcu_read_lock_bh();
	ret = walk_ips_by_peer(table->root4, AF_INET, ctx, peer, func, NULL);
	rcu_read_unlock_bh();
	if (ret)
		return ret;
	rcu_read_lock_bh();
	ret = walk_ips_by_peer(table->root6, AF_INET6, ctx, peer, func, NULL);
	rcu_read_unlock_bh();
	return ret;
}

int routing_table_walk_ips_by_peer_sleepable(struct routing_table *table, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, u8 cidr, int family))
{
	int ret;
	mutex_lock(&table->table_update_lock);
	ret = walk_ips_by_peer(table->root4, AF_INET, ctx, peer, func, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	if (ret)
		return ret;
	mutex_lock(&table->table_update_lock);
	ret = walk_ips_by_peer(table->root6, AF_INET6, ctx, peer, func, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return ret;
}

static inline bool has_valid_ip_header(struct sk_buff *skb)
{
	if (unlikely(skb->len < sizeof(struct iphdr)))
		return false;
	else if (unlikely(skb->len < sizeof(struct ipv6hdr) && ip_hdr(skb)->version == 6))
		return false;
	else if (unlikely(ip_hdr(skb)->version != 4 && ip_hdr(skb)->version != 6))
		return false;
	return true;
}

/* Returns a strong reference to a peer */
struct wireguard_peer *routing_table_lookup_dst(struct routing_table *table, struct sk_buff *skb)
{
	if (unlikely(!has_valid_ip_header(skb)))
		return NULL;
	if (ip_hdr(skb)->version == 4)
		return lookup(table->root4, 32, &ip_hdr(skb)->daddr);
	else if (ip_hdr(skb)->version == 6)
		return lookup(table->root6, 128, &ipv6_hdr(skb)->daddr);
	return NULL;
}

/* Returns a strong reference to a peer */
struct wireguard_peer *routing_table_lookup_src(struct routing_table *table, struct sk_buff *skb)
{
	if (unlikely(!has_valid_ip_header(skb)))
		return NULL;
	if (ip_hdr(skb)->version == 4)
		return lookup(table->root4, 32, &ip_hdr(skb)->saddr);
	else if (ip_hdr(skb)->version == 6)
		return lookup(table->root6, 128, &ipv6_hdr(skb)->saddr);
	return NULL;
}

#include "selftest/routingtable.h"
