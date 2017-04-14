/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef ROUTINGTABLE_H
#define ROUTINGTABLE_H

#include <linux/mutex.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct wireguard_peer;
struct routing_table_node;

struct routing_table {
	struct routing_table_node __rcu *root4;
	struct routing_table_node __rcu *root6;
	struct mutex table_update_lock;
};

void routing_table_init(struct routing_table *table);
void routing_table_free(struct routing_table *table);
int routing_table_insert_v4(struct routing_table *table, const struct in_addr *ip, u8 cidr, struct wireguard_peer *peer);
int routing_table_insert_v6(struct routing_table *table, const struct in6_addr *ip, u8 cidr, struct wireguard_peer *peer);
void routing_table_remove_by_peer(struct routing_table *table, struct wireguard_peer *peer);
size_t routing_table_count_nodes(struct routing_table *table);
int routing_table_walk_ips_by_peer(struct routing_table *table, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, u8 cidr, int family));
int routing_table_walk_ips_by_peer_sleepable(struct routing_table *table, void *ctx, struct wireguard_peer *peer, int (*func)(void *ctx, union nf_inet_addr ip, u8 cidr, int family));

/* These return a strong reference to a peer: */
struct wireguard_peer *routing_table_lookup_dst(struct routing_table *table, struct sk_buff *skb);
struct wireguard_peer *routing_table_lookup_src(struct routing_table *table, struct sk_buff *skb);

#ifdef DEBUG
bool routing_table_selftest(void);
#endif

#endif
