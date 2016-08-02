/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "wireguard.h"
#include "routing-table.h"

struct routing_table_node {
	struct routing_table_node __rcu *bit[2];
	struct rcu_head rcu;
	struct wireguard_peer *peer;
	uint8_t cidr;
	uint8_t bit_at_a, bit_at_b;
	bool incidental;
	uint8_t bits[];
};

static inline uint8_t bit_at(const uint8_t *key, uint8_t a, uint8_t b)
{
	return (key[a] >> b) & 1;
}
static inline void assign_cidr(struct routing_table_node *node, uint8_t cidr)
{
	node->cidr = cidr;
	node->bit_at_a = cidr / 8;
	node->bit_at_b = 7 - (cidr % 8);
}

/* Non-recursive RCU expansion of:
 *
 * free_node(node)
 * {
 *     if (!node)
 *       return;
 *     free_node(node->bit[0]);
 *     free_node(node->bit[1]);
 *     kfree_rcu(node);
 * }
 */
#define ref(p) rcu_access_pointer(p)
#define push(p) do { BUG_ON(len >= 128); stack[len++] = rcu_dereference_protected(p, lockdep_is_held(lock)); } while (0)
static void free_node(struct routing_table_node *top, struct mutex *lock)
{
	struct routing_table_node *stack[128];
	struct routing_table_node *node = NULL;
	struct routing_table_node *prev = NULL;
	unsigned int len = 0;

	if (!top)
		return;

	stack[len++] = top;
	while (len > 0) {
		node = stack[len - 1];
		if (!prev || ref(prev->bit[0]) == node || ref(prev->bit[1]) == node) {
			if (ref(node->bit[0]))
				push(node->bit[0]);
			else if (ref(node->bit[1]))
				push(node->bit[1]);
		} else if (ref(node->bit[0]) == prev) {
			if (ref(node->bit[1]))
				push(node->bit[1]);
		} else {
			kfree_rcu(node, rcu);
			--len;
		}
		prev = node;
	}
}
#undef push
#define push(p) do { BUG_ON(len >= 128); stack[len++] = p; } while (0)
static bool walk_remove_by_peer(struct routing_table_node __rcu **top, struct wireguard_peer *peer, struct mutex *lock)
{
	struct routing_table_node __rcu **stack[128];
	struct routing_table_node __rcu **nptr;
	struct routing_table_node *node = NULL;
	struct routing_table_node *prev = NULL;
	unsigned int len = 0;
	bool ret = false;

	stack[len++] = top;
	while (len > 0) {
		nptr = stack[len - 1];
		node = rcu_dereference_protected(*nptr, lockdep_is_held(lock));
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
				ret = true;
				node->peer = NULL;
				node->incidental = true;
				if (!node->bit[0] || !node->bit[1]) {
					/* collapse (even if both are null) */
					rcu_assign_pointer(*nptr, rcu_dereference_protected(node->bit[!node->bit[0]], lockdep_is_held(lock)));
					rcu_assign_pointer(node->bit[0], NULL);
					rcu_assign_pointer(node->bit[1], NULL);
					free_node(node, lock);
				}
			}
			--len;
		}
		prev = node;
	}

	return ret;
}
#undef ref
#undef push

static inline bool match(const struct routing_table_node *node, const uint8_t *key, uint8_t match_len)
{
	uint8_t full_blocks_to_match = match_len / 8;
	uint8_t bits_leftover = match_len % 8;
	uint8_t mask;
	const uint8_t *a = node->bits, *b = key;
	if (memcmp(a, b, full_blocks_to_match))
		return false;
	if (!bits_leftover)
		return true;
	mask = ~(0xff >> bits_leftover);
	return (a[full_blocks_to_match] & mask) == (b[full_blocks_to_match] & mask);
}

static inline uint8_t common_bits(const struct routing_table_node *node, const uint8_t *key, uint8_t match_len)
{
	uint8_t max = (((match_len > node->cidr) ? match_len : node->cidr) + 7) / 8;
	uint8_t bits = 0;
	uint8_t i, mask;
	const uint8_t *a = node->bits, *b = key;
	for (i = 0; i < max; ++i, bits += 8) {
		if (a[i] != b[i])
			break;
	}
	if (i == max)
		return bits;
	for (mask = 128; mask > 0; mask /= 2, ++bits) {
		if ((a[i] & mask) != (b[i] & mask))
			return bits;
	}
	BUG();
	return bits;
}

static int remove(struct routing_table_node __rcu **trie, const uint8_t *key, uint8_t cidr, struct mutex *lock)
{
	struct routing_table_node *parent = NULL, *node;
	node = rcu_dereference_protected(*trie, lockdep_is_held(lock));
	while (node && node->cidr <= cidr && match(node, key, node->cidr)) {
		if (node->cidr == cidr) {
			/* exact match */
			node->incidental = true;
			node->peer = NULL;
			if (!node->bit[0] || !node->bit[1]) {
				/* collapse (even if both are null) */
				if (parent)
					rcu_assign_pointer(parent->bit[bit_at(key, parent->bit_at_a, parent->bit_at_b)],
							   rcu_dereference_protected(node->bit[(!node->bit[0]) ? 1 : 0], lockdep_is_held(lock)));
				rcu_assign_pointer(node->bit[0], NULL);
				rcu_assign_pointer(node->bit[1], NULL);
				free_node(node, lock);
			}
			return 0;
		}
		parent = node;
		node = rcu_dereference_protected(parent->bit[bit_at(key, parent->bit_at_a, parent->bit_at_b)], lockdep_is_held(lock));
	}
	return -ENOENT;
}

static inline struct routing_table_node *find_node(struct routing_table_node *trie, uint8_t bits, const uint8_t *key)
{
	struct routing_table_node *node = trie, *found = NULL;
	while (node && match(node, key, node->cidr)) {
		if (!node->incidental)
			found = node;
		if (node->cidr == bits)
			break;
		node = rcu_dereference(node->bit[bit_at(key, node->bit_at_a, node->bit_at_b)]);
	}
	return found;
}

static inline bool node_placement(struct routing_table_node __rcu *trie, const uint8_t *key, uint8_t cidr, struct routing_table_node **rnode, struct mutex *lock)
{
	bool exact = false;
	struct routing_table_node *parent = NULL, *node = rcu_dereference_protected(trie, lockdep_is_held(lock));
	while (node && node->cidr <= cidr && match(node, key, node->cidr)) {
		parent = node;
		if (parent->cidr == cidr) {
			exact = true;
			break;
		}
		node = rcu_dereference_protected(parent->bit[bit_at(key, parent->bit_at_a, parent->bit_at_b)], lockdep_is_held(lock));
	}
	if (rnode)
		*rnode = parent;
	return exact;
}

static int add(struct routing_table_node __rcu **trie, uint8_t bits, const uint8_t *key, uint8_t cidr, struct wireguard_peer *peer, struct mutex *lock)
{
	struct routing_table_node *node, *parent, *down, *newnode;
	int bits_in_common;

	if (!rcu_access_pointer(*trie)) {
		node = kzalloc(sizeof(*node) + (bits + 7) / 8, GFP_KERNEL);
		if (!node)
			return -ENOMEM;
		node->peer = peer;
		memcpy(node->bits, key, (bits + 7) / 8);
		assign_cidr(node, cidr);
		rcu_assign_pointer(*trie, node);
		return 0;
	}
	if (node_placement(*trie, key, cidr, &node, lock)) {
		/* exact match */
		node->incidental = false;
		node->peer = peer;
		return 0;
	}

	newnode = kzalloc(sizeof(*node) + (bits + 7) / 8, GFP_KERNEL);
	if (!newnode)
		return -ENOMEM;
	newnode->peer = peer;
	memcpy(newnode->bits, key, (bits + 7) / 8);
	assign_cidr(newnode, cidr);

	if (!node)
		down = rcu_dereference_protected(*trie, lockdep_is_held(lock));
	else
		down = rcu_dereference_protected(node->bit[bit_at(key, node->bit_at_a, node->bit_at_b)], lockdep_is_held(lock));
	if (!down) {
		rcu_assign_pointer(node->bit[bit_at(key, node->bit_at_a, node->bit_at_b)], newnode);
		return 0;
	}
	/* here we must be inserting between node and down */
	bits_in_common = common_bits(down, key, cidr);
	parent = node;
	if (bits_in_common > cidr)
		bits_in_common = cidr;

	/* we either need to make a new branch above down and newnode
	 * or newnode can be the branch. newnode can be the branch if
	 * its cidr == bits_in_common */
	if (newnode->cidr == bits_in_common) {
		/* newnode can be the branch */
		rcu_assign_pointer(newnode->bit[bit_at(down->bits, newnode->bit_at_a, newnode->bit_at_b)], down);
		if (!parent)
			rcu_assign_pointer(*trie, newnode);
		else
			rcu_assign_pointer(parent->bit[bit_at(newnode->bits, parent->bit_at_a, parent->bit_at_b)], newnode);
	} else {
		/* reparent */
		node = kzalloc(sizeof(*node) + (bits + 7) / 8, GFP_KERNEL);
		if (!node) {
			kfree(newnode);
			return -ENOMEM;
		}
		assign_cidr(node, bits_in_common);
		node->incidental = true;
		memcpy(node->bits, newnode->bits, (bits + 7) / 8);
		rcu_assign_pointer(node->bit[bit_at(down->bits, node->bit_at_a, node->bit_at_b)], down);
		rcu_assign_pointer(node->bit[bit_at(newnode->bits, node->bit_at_a, node->bit_at_b)], newnode);
		if (!parent)
			rcu_assign_pointer(*trie, node);
		else
			rcu_assign_pointer(parent->bit[bit_at(node->bits, parent->bit_at_a, parent->bit_at_b)], node);
	}
	return 0;
}

#define push(p) do { \
	struct routing_table_node *next = (maybe_lock ? rcu_dereference_protected(p, lockdep_is_held(maybe_lock)) : rcu_dereference(p)); \
	if (next) { \
		BUG_ON(len >= 128); \
		stack[len++] = next; \
	} \
} while (0)
static int walk_ips(struct routing_table_node *top, int family, void *ctx, int (*func)(void *ctx, struct wireguard_peer *peer, union nf_inet_addr ip, uint8_t cidr, int family), struct mutex *maybe_lock)
{
	int ret;
	union nf_inet_addr ip = { .all = { 0 } };
	struct routing_table_node *stack[128];
	struct routing_table_node *node;
	unsigned int len = 0;
	struct wireguard_peer *peer;

	if (!top)
		return 0;

	stack[len++] = top;
	while (len > 0) {
		node = stack[--len];

		peer = peer_get(node->peer);
		if (peer) {
			memcpy(ip.all, node->bits, family == AF_INET6 ? 16 : 4);
			ret = func(ctx, peer, ip, node->cidr, family);
			peer_put(peer);
			if (ret)
				return ret;
		}

		push(node->bit[0]);
		push(node->bit[1]);
	}
	return 0;
}
static int walk_ips_by_peer(struct routing_table_node *top, int family, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, uint8_t cidr, int family), struct mutex *maybe_lock)
{
	int ret;
	union nf_inet_addr ip = { .all = { 0 } };
	struct routing_table_node *stack[128];
	struct routing_table_node *node;
	unsigned int len = 0;

	if (!top)
		return 0;

	stack[len++] = top;
	while (len > 0) {
		node = stack[--len];

		if (node->peer == peer) {
			memcpy(ip.all, node->bits, family == AF_INET6 ? 16 : 4);
			ret = func(ctx, ip, node->cidr, family);
			if (ret)
				return ret;
		}

		push(node->bit[0]);
		push(node->bit[1]);
	}
	return 0;
}
#undef push

void routing_table_init(struct routing_table *table)
{
	memset(table, 0, sizeof(struct routing_table));
	mutex_init(&table->table_update_lock);
}

void routing_table_free(struct routing_table *table)
{
	mutex_lock(&table->table_update_lock);
	free_node(rcu_dereference_protected(table->root4, lockdep_is_held(&table->table_update_lock)), &table->table_update_lock);
	rcu_assign_pointer(table->root4, NULL);
	free_node(rcu_dereference_protected(table->root6, lockdep_is_held(&table->table_update_lock)), &table->table_update_lock);
	rcu_assign_pointer(table->root6, NULL);
	mutex_unlock(&table->table_update_lock);
}

int routing_table_insert_v4(struct routing_table *table, const struct in_addr *ip, uint8_t cidr, struct wireguard_peer *peer)
{
	int ret;
	if (cidr > 32)
		return -EINVAL;
	mutex_lock(&table->table_update_lock);
	ret = add(&table->root4, 32, (const uint8_t *)ip, cidr, peer, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return ret;
}

int routing_table_insert_v6(struct routing_table *table, const struct in6_addr *ip, uint8_t cidr, struct wireguard_peer *peer)
{
	int ret;
	if (cidr > 128)
		return -EINVAL;
	mutex_lock(&table->table_update_lock);
	ret = add(&table->root6, 128, (const uint8_t *)ip, cidr, peer, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return ret;
}

/* Returns a strong reference to a peer */
inline struct wireguard_peer *routing_table_lookup_v4(struct routing_table *table, const struct in_addr *ip)
{
	struct wireguard_peer *peer = NULL;
	struct routing_table_node *node;

	rcu_read_lock();
	node = find_node(rcu_dereference(table->root4), 32, (const uint8_t *)ip);
	if (node)
		peer = peer_get(node->peer);
	rcu_read_unlock();
	return peer;
}

/* Returns a strong reference to a peer */
inline struct wireguard_peer *routing_table_lookup_v6(struct routing_table *table, const struct in6_addr *ip)
{
	struct wireguard_peer *peer = NULL;
	struct routing_table_node *node;

	rcu_read_lock();
	node = find_node(rcu_dereference(table->root6), 128, (const uint8_t *)ip);
	if (node)
		peer = peer_get(node->peer);
	rcu_read_unlock();
	return peer;
}

int routing_table_remove_v4(struct routing_table *table, const struct in_addr *ip, uint8_t cidr)
{
	int ret;
	mutex_lock(&table->table_update_lock);
	ret = remove(&table->root4, (const uint8_t *)ip, cidr, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return ret;
}

int routing_table_remove_v6(struct routing_table *table, const struct in6_addr *ip, uint8_t cidr)
{
	int ret;
	mutex_lock(&table->table_update_lock);
	ret = remove(&table->root6, (const uint8_t *)ip, cidr, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return ret;
}

int routing_table_remove_by_peer(struct routing_table *table, struct wireguard_peer *peer)
{
	bool found;
	mutex_lock(&table->table_update_lock);
	found = walk_remove_by_peer(&table->root4, peer, &table->table_update_lock) | walk_remove_by_peer(&table->root6, peer, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	return found ? 0 : -EINVAL;
}

/* Calls func with a strong reference to each peer, before putting it when the function has completed.
 * It's thus up to the caller to call peer_put on it if it's going to be used elsewhere after or stored. */
int routing_table_walk_ips(struct routing_table *table, void *ctx, int (*func)(void *ctx, struct wireguard_peer *peer, union nf_inet_addr ip, uint8_t cidr, int family))
{
	int ret;
	rcu_read_lock();
	ret = walk_ips(rcu_dereference(table->root4), AF_INET, ctx, func, NULL);
	rcu_read_unlock();
	if (ret)
		return ret;
	rcu_read_lock();
	ret = walk_ips(rcu_dereference(table->root6), AF_INET6, ctx, func, NULL);
	rcu_read_unlock();
	return ret;
}

int routing_table_walk_ips_by_peer(struct routing_table *table, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, uint8_t cidr, int family))
{
	int ret;
	rcu_read_lock();
	ret = walk_ips_by_peer(rcu_dereference(table->root4), AF_INET, ctx, peer, func, NULL);
	rcu_read_unlock();
	if (ret)
		return ret;
	rcu_read_lock();
	ret = walk_ips_by_peer(rcu_dereference(table->root6), AF_INET6, ctx, peer, func, NULL);
	rcu_read_unlock();
	return ret;
}

int routing_table_walk_ips_by_peer_sleepable(struct routing_table *table, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, uint8_t cidr, int family))
{
	int ret;
	mutex_lock(&table->table_update_lock);
	ret = walk_ips_by_peer(rcu_dereference_protected(table->root4, lockdep_is_held(&table->table_update_lock)), AF_INET, ctx, peer, func, &table->table_update_lock);
	mutex_unlock(&table->table_update_lock);
	if (ret)
		return ret;
	mutex_lock(&table->table_update_lock);
	ret = walk_ips_by_peer(rcu_dereference_protected(table->root6, lockdep_is_held(&table->table_update_lock)), AF_INET6, ctx, peer, func, &table->table_update_lock);
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
		return routing_table_lookup_v4(table, (struct in_addr *)&ip_hdr(skb)->daddr);
	else if (ip_hdr(skb)->version == 6)
		return routing_table_lookup_v6(table, &ipv6_hdr(skb)->daddr);
	return NULL;
}

/* Returns a strong reference to a peer */
struct wireguard_peer *routing_table_lookup_src(struct routing_table *table, struct sk_buff *skb)
{
	if (unlikely(!has_valid_ip_header(skb)))
		return NULL;
	if (ip_hdr(skb)->version == 4)
		return routing_table_lookup_v4(table, (struct in_addr *)&ip_hdr(skb)->saddr);
	else if (ip_hdr(skb)->version == 6)
		return routing_table_lookup_v6(table, &ipv6_hdr(skb)->saddr);
	return NULL;
}

#include "selftest/routing-table.h"
