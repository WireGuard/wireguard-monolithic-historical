/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "ratelimiter.h"
#include <linux/siphash.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <net/ip.h>

static struct kmem_cache *entry_cache;
static hsiphash_key_t key;
static spinlock_t table_lock = __SPIN_LOCK_UNLOCKED("ratelimiter_table_lock");
static DEFINE_MUTEX(init_lock);
static atomic64_t refcnt = ATOMIC64_INIT(0);
static atomic_t total_entries = ATOMIC_INIT(0);
static unsigned int max_entries, table_size;
static void gc_entries(struct work_struct *);
static DECLARE_DEFERRABLE_WORK(gc_work, gc_entries);
static struct hlist_head *table_v4;
#if IS_ENABLED(CONFIG_IPV6)
static struct hlist_head *table_v6;
#endif

struct ratelimiter_entry {
	u64 last_time_ns, tokens;
	__be64 ip;
	void *net;
	spinlock_t lock;
	struct hlist_node hash;
	struct rcu_head rcu;
};

enum {
	PACKETS_PER_SECOND = 20,
	PACKETS_BURSTABLE = 5,
	PACKET_COST = NSEC_PER_SEC / PACKETS_PER_SECOND,
	TOKEN_MAX = PACKET_COST * PACKETS_BURSTABLE
};

static void entry_free(struct rcu_head *rcu)
{
	kmem_cache_free(entry_cache,
			container_of(rcu, struct ratelimiter_entry, rcu));
	atomic_dec(&total_entries);
}

static void entry_uninit(struct ratelimiter_entry *entry)
{
	hlist_del_rcu(&entry->hash);
	call_rcu(&entry->rcu, entry_free);
}

/* Calling this function with a NULL work uninits all entries. */
static void gc_entries(struct work_struct *work)
{
	const u64 now = ktime_get_boot_fast_ns();
	struct ratelimiter_entry *entry;
	struct hlist_node *temp;
	unsigned int i;

	for (i = 0; i < table_size; ++i) {
		spin_lock(&table_lock);
		hlist_for_each_entry_safe (entry, temp, &table_v4[i], hash) {
			if (unlikely(!work) ||
			    now - entry->last_time_ns > NSEC_PER_SEC)
				entry_uninit(entry);
		}
#if IS_ENABLED(CONFIG_IPV6)
		hlist_for_each_entry_safe (entry, temp, &table_v6[i], hash) {
			if (unlikely(!work) ||
			    now - entry->last_time_ns > NSEC_PER_SEC)
				entry_uninit(entry);
		}
#endif
		spin_unlock(&table_lock);
		if (likely(work))
			cond_resched();
	}
	if (likely(work))
		queue_delayed_work(system_power_efficient_wq, &gc_work, HZ);
}

bool ratelimiter_allow(struct sk_buff *skb, struct net *net)
{
	struct { __be64 ip; u32 net; } data = {
		.net = (unsigned long)net & 0xffffffff };
	struct ratelimiter_entry *entry;
	struct hlist_head *bucket;

	if (skb->protocol == htons(ETH_P_IP)) {
		data.ip = (__force __be64)ip_hdr(skb)->saddr;
		bucket = &table_v4[hsiphash(&data, sizeof(u32) * 3, &key) &
				   (table_size - 1)];
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		memcpy(&data.ip, &ipv6_hdr(skb)->saddr,
		       sizeof(__be64)); /* Only 64 bits */
		bucket = &table_v6[hsiphash(&data, sizeof(u32) * 3, &key) &
				   (table_size - 1)];
	}
#endif
	else
		return false;
	rcu_read_lock();
	hlist_for_each_entry_rcu (entry, bucket, hash) {
		if (entry->net == net && entry->ip == data.ip) {
			u64 now, tokens;
			bool ret;
			/* Quasi-inspired by nft_limit.c, but this is actually a
			 * slightly different algorithm. Namely, we incorporate
			 * the burst as part of the maximum tokens, rather than
			 * as part of the rate.
			 */
			spin_lock(&entry->lock);
			now = ktime_get_boot_fast_ns();
			tokens = min_t(u64, TOKEN_MAX,
				       entry->tokens + now -
					       entry->last_time_ns);
			entry->last_time_ns = now;
			ret = tokens >= PACKET_COST;
			entry->tokens = ret ? tokens - PACKET_COST : tokens;
			spin_unlock(&entry->lock);
			rcu_read_unlock();
			return ret;
		}
	}
	rcu_read_unlock();

	if (atomic_inc_return(&total_entries) > max_entries)
		goto err_oom;

	entry = kmem_cache_alloc(entry_cache, GFP_KERNEL);
	if (unlikely(!entry))
		goto err_oom;

	entry->net = net;
	entry->ip = data.ip;
	INIT_HLIST_NODE(&entry->hash);
	spin_lock_init(&entry->lock);
	entry->last_time_ns = ktime_get_boot_fast_ns();
	entry->tokens = TOKEN_MAX - PACKET_COST;
	spin_lock(&table_lock);
	hlist_add_head_rcu(&entry->hash, bucket);
	spin_unlock(&table_lock);
	return true;

err_oom:
	atomic_dec(&total_entries);
	return false;
}

int ratelimiter_init(void)
{
	mutex_lock(&init_lock);
	if (atomic64_inc_return(&refcnt) != 1)
		goto out;

	entry_cache = KMEM_CACHE(ratelimiter_entry, 0);
	if (!entry_cache)
		goto err;

	/* xt_hashlimit.c uses a slightly different algorithm for ratelimiting,
	 * but what it shares in common is that it uses a massive hashtable. So,
	 * we borrow their wisdom about good table sizes on different systems
	 * dependent on RAM. This calculation here comes from there.
	 */
	table_size = (totalram_pages > (1U << 30) / PAGE_SIZE) ? 8192 :
		max_t(unsigned long, 16, roundup_pow_of_two(
			(totalram_pages << PAGE_SHIFT) /
			(1U << 14) / sizeof(struct hlist_head)));
	max_entries = table_size * 8;

	table_v4 = kvzalloc(table_size * sizeof(*table_v4), GFP_KERNEL);
	if (unlikely(!table_v4))
		goto err_kmemcache;

#if IS_ENABLED(CONFIG_IPV6)
	table_v6 = kvzalloc(table_size * sizeof(*table_v6), GFP_KERNEL);
	if (unlikely(!table_v6)) {
		kvfree(table_v4);
		goto err_kmemcache;
	}
#endif

	queue_delayed_work(system_power_efficient_wq, &gc_work, HZ);
	get_random_bytes(&key, sizeof(key));
out:
	mutex_unlock(&init_lock);
	return 0;

err_kmemcache:
	kmem_cache_destroy(entry_cache);
err:
	atomic64_dec(&refcnt);
	mutex_unlock(&init_lock);
	return -ENOMEM;
}

void ratelimiter_uninit(void)
{
	mutex_lock(&init_lock);
	if (atomic64_dec_if_positive(&refcnt))
		goto out;

	cancel_delayed_work_sync(&gc_work);
	gc_entries(NULL);
	rcu_barrier();
	kvfree(table_v4);
#if IS_ENABLED(CONFIG_IPV6)
	kvfree(table_v6);
#endif
	kmem_cache_destroy(entry_cache);
out:
	mutex_unlock(&init_lock);
}

#include "selftest/ratelimiter.h"
