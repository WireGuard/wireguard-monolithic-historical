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
#ifdef DEBUG
static inline struct in_addr *ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
	static struct in_addr ip;
	uint8_t *split = (uint8_t *)&ip;
	split[0] = a;
	split[1] = b;
	split[2] = c;
	split[3] = d;
	return &ip;
}
static inline struct in6_addr *ip6(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	static struct in6_addr ip;
	__be32 *split = (__be32 *)&ip;
	split[0] = cpu_to_be32(a);
	split[1] = cpu_to_be32(b);
	split[2] = cpu_to_be32(c);
	split[3] = cpu_to_be32(d);
	return &ip;
}

bool routing_table_selftest(void)
{
	struct routing_table t;
	struct wireguard_peer *a = NULL, *b = NULL, *c = NULL, *d = NULL, *e = NULL, *f = NULL, *g = NULL, *h = NULL;
	size_t i = 0;
	bool success = false;
	struct in6_addr ip;
	__be64 part;

	routing_table_init(&t);
#define init_peer(name) do { name = kzalloc(sizeof(struct wireguard_peer), GFP_KERNEL); if (!name) goto free; kref_init(&name->refcount); } while (0)
	init_peer(a);
	init_peer(b);
	init_peer(c);
	init_peer(d);
	init_peer(e);
	init_peer(f);
	init_peer(g);
	init_peer(h);
#undef init_peer

#define insert(version, mem, ipa, ipb, ipc, ipd, cidr) routing_table_insert_v##version(&t, ip##version(ipa, ipb, ipc, ipd), cidr, mem)
	insert(4, a, 192, 168, 4, 0, 24);
	insert(4, b, 192, 168, 4, 4, 32);
	insert(4, c, 192, 168, 0, 0, 16);
	insert(4, d, 192, 95, 5, 64, 27);
	insert(4, c, 192, 95, 5, 65, 27); /* replaces previous entry, and maskself is required */
	insert(6, d, 0x26075300, 0x60006b00, 0, 0xc05f0543, 128);
	insert(6, c, 0x26075300, 0x60006b00, 0, 0, 64);
	insert(4, e, 0, 0, 0, 0, 0);
	insert(6, e, 0, 0, 0, 0, 0);
	insert(6, f, 0, 0, 0, 0, 0); /* replaces previous entry */
	insert(6, g, 0x24046800, 0, 0, 0, 32);
	insert(6, h, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 64); /* maskself is required */
	insert(6, a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef, 128);
	insert(4, g, 64, 15, 112, 0, 20);
	insert(4, h, 64, 15, 123, 211, 25); /* maskself is required */
#undef insert

	success = true;
#define test(version, mem, ipa, ipb, ipc, ipd) do { \
	bool _s = routing_table_lookup_v##version(&t, ip##version(ipa, ipb, ipc, ipd)) == mem; \
	++i; \
	if (!_s) { \
		pr_info("routing table self-test %zu: FAIL\n", i); \
		success = false; \
	} \
} while (0)
	test(4, a, 192, 168, 4, 20);
	test(4, a, 192, 168, 4, 0);
	test(4, b, 192, 168, 4, 4);
	test(4, c, 192, 168, 200, 182);
	test(4, c, 192, 95, 5, 68);
	test(4, e, 192, 95, 5, 96);
	test(6, d, 0x26075300, 0x60006b00, 0, 0xc05f0543);
	test(6, c, 0x26075300, 0x60006b00, 0, 0xc02e01ee);
	test(6, f, 0x26075300, 0x60006b01, 0, 0);
	test(6, g, 0x24046800, 0x40040806, 0, 0x1006);
	test(6, g, 0x24046800, 0x40040806, 0x1234, 0x5678);
	test(6, f, 0x240467ff, 0x40040806, 0x1234, 0x5678);
	test(6, f, 0x24046801, 0x40040806, 0x1234, 0x5678);
	test(6, h, 0x24046800, 0x40040800, 0x1234, 0x5678);
	test(6, h, 0x24046800, 0x40040800, 0, 0);
	test(6, h, 0x24046800, 0x40040800, 0x10101010, 0x10101010);
	test(6, a, 0x24046800, 0x40040800, 0xdeadbeef, 0xdeadbeef);
	test(4, g, 64, 15, 116, 26);
	test(4, g, 64, 15, 127, 3);
	test(4, g, 64, 15, 123, 1);
	test(4, h, 64, 15, 123, 128);
	test(4, h, 64, 15, 123, 129);
#undef test

	/* These will hit the BUG_ON(len >= 128) in free_node if something goes wrong. */
	for (i = 0; i < 128; ++i) {
		part = cpu_to_be64(~(1LLU << (i % 64)));
		memset(&ip, 0xff, 16);
		memcpy((uint8_t *)&ip + (i < 64) * 8, &part, 8);
		routing_table_insert_v6(&t, &ip, 128, a);
	}

	if (success)
		pr_info("routing table self-tests: pass\n");

free:
	routing_table_free(&t);
	kfree(a);
	kfree(b);
	kfree(c);
	kfree(d);
	kfree(e);
	kfree(f);
	kfree(g);
	kfree(h);

	return success;
}
#endif
