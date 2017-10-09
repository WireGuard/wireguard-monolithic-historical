/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef _WG_ROUTINGTABLE_H
#define _WG_ROUTINGTABLE_H

#include <linux/mutex.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct wireguard_peer;
struct routing_table_node;

struct routing_table {
	struct routing_table_node __rcu *root4;
	struct routing_table_node __rcu *root6;
	u64 seq;
};

struct routing_table_cursor {
	u64 seq;
	struct routing_table_node *stack[128];
	unsigned int len;
	bool second_half;
};

void routing_table_init(struct routing_table *table);
void routing_table_free(struct routing_table *table, struct mutex *mutex);
int routing_table_insert_v4(struct routing_table *table, const struct in_addr *ip, u8 cidr, struct wireguard_peer *peer, struct mutex *lock);
int routing_table_insert_v6(struct routing_table *table, const struct in6_addr *ip, u8 cidr, struct wireguard_peer *peer, struct mutex *lock);
void routing_table_remove_by_peer(struct routing_table *table, struct wireguard_peer *peer, struct mutex *lock);
int routing_table_walk_by_peer(struct routing_table *table, struct routing_table_cursor *cursor, struct wireguard_peer *peer, int (*func)(void *ctx, const u8 *ip, u8 cidr, int family), void *ctx, struct mutex *lock);

/* These return a strong reference to a peer: */
struct wireguard_peer *routing_table_lookup_dst(struct routing_table *table, struct sk_buff *skb);
struct wireguard_peer *routing_table_lookup_src(struct routing_table *table, struct sk_buff *skb);

#ifdef DEBUG
bool routing_table_selftest(void);
#endif

#endif /* _WG_ROUTINGTABLE_H */
