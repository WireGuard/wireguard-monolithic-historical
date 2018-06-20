/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jonathan Neuschäfer
 * Copyright (C) 2018 Thomas Gschwantner <tharre3@gmail.com>. All Rights Reserved.
 */

#ifndef MPMC_RING_PTR_H
#define MPMC_RING_PTR_H

/*
 * This is an implementation of a Multi-Producer/Multi-Consumer (MPMC) queue,
 * strongly inspired by ConcurrencyKit[1], and Linux's own ptr_ring.h.
 *
 *
 *              +-----------------------------------------------+
 *        index | 0| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15|
 *        state |--|--|--|**|**|**|**|**|**|**|++|++|++|--|--|--|
 *              +-----------------------------------------------+
 *                        ^                    ^        ^
 *                        consumer head        |        producer head
 *                                             producer tail
 * Possible states:
 *
 *  -- : unoccupied
 *  ++ : being written
 *  ** : occupied
 *
 * Differences between ptr_ring.h and this implementation:
 * - An additional producer tail pointer, which allows multiple enqueue
 *   operations to be in progress at the same time.
 * - No consumer tail pointer, for simplicity (although I expect it can be
 *   added later)
 * - Most importantly: No spinlocks.
 * - The head/tail pointers (or rather: indices) are stored untrimmed, i.e.
 *   without the bit mask (size - 1) applied, because that's how ConcurrencyKit
 *   does it.
 *
 * [1]: https://github.com/concurrencykit/ck/blob/master/include/ck_ring.h
 */

#include <asm/barrier.h>
#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/log2.h>
#include <linux/processor.h>
#include <linux/slab.h>
#include <linux/stddef.h>


struct mpmc_ptr_ring {
	/* Read-mostly data */
	void **queue;
	unsigned int size;
	unsigned int mask;

	/* consumer_head: updated in _consume; read in _produce */
	atomic_t consumer_head ____cacheline_aligned_in_smp;

	/* producer_{head,tail}: updated in _produce */
	atomic_t producer_head ____cacheline_aligned_in_smp;
	atomic_t producer_tail;
};

static inline bool mpmc_ptr_ring_empty(struct mpmc_ptr_ring *r)
{
	unsigned int ptail, chead;

	/* Order the following reads against earlier stuff */
	smp_rmb();

	ptail = atomic_read(&r->producer_tail);
	chead = atomic_read(&r->consumer_head);

	return chead == ptail;
}

static inline int mpmc_ptr_ring_produce(struct mpmc_ptr_ring *r, void *ptr)
{
	int p, c;
	unsigned int mask = r->mask;

	p = atomic_read(&r->producer_head);

	for (;;) {
		smp_rmb();	 /* TODO */
		c = atomic_read(&r->consumer_head);

		if ((p - c) < mask) { /* fast path */
			if (atomic_try_cmpxchg_relaxed(&r->producer_head, &p, p + 1))
				break;
		} else {
			int new_p;

			smp_rmb();
			new_p = atomic_read(&r->producer_head);

			if (new_p == p)
				return -ENOSPC;

			p = new_p;
		}
	}

	WRITE_ONCE(r->queue[p & mask], ptr);

	/* Wait until it's our turn to update the producer tail pointer */
	while (atomic_read(&r->producer_tail) != p)
		cpu_relax();

	/*
	 * Make sure the WRITE_ONCE above becomes visible before producer_tail
	 * is updated.
	 */
	smp_wmb();
	atomic_set(&r->producer_tail, p + 1);

	return 0;
}

static inline void *mpmc_ptr_ring_consume(struct mpmc_ptr_ring *r)
{
	int c, p;
	unsigned int mask = r->mask;
	void *element;

	do {
		c = atomic_read(&r->consumer_head);

		/* Fetch consumer_head first. */
		smp_rmb();

		p = atomic_read(&r->producer_tail);

		/* Is the ring empty? */
		if (p == c)
			return NULL;

		element = READ_ONCE(r->queue[c & mask]);

		/*
		 * Stores to consumer_head must be completed before we update
		 * the head, so we use *_release.
		 */
	} while (!atomic_try_cmpxchg_release(&r->consumer_head, &c, c + 1));

	return element;
}

/*
 * Warning: size must be greater than the number of concurrent consumers
 */
static inline int mpmc_ptr_ring_init(struct mpmc_ptr_ring *r, unsigned int size, gfp_t gfp)
{
	if (WARN_ONCE(!is_power_of_2(size), "size must be a power of two"))
		return -EINVAL;

	r->size = size;
	r->mask = size - 1;
	atomic_set(&r->consumer_head, 0);
	atomic_set(&r->producer_head, 0);
	atomic_set(&r->producer_tail, 0);

	r->queue = kcalloc(size, sizeof(r->queue[0]), gfp);
	if (!r->queue)
		return -ENOMEM;

	return 0;
}

static inline void mpmc_ptr_ring_cleanup(struct mpmc_ptr_ring *r, void (*destroy)(void *))
{
	void *ptr;

	if (destroy)
		while ((ptr = mpmc_ptr_ring_consume(r)))
			destroy(ptr);
	kfree(r->queue);
}

/**
 * __mpmc_ptr_ring_peek - Read the first element in an MPMC ring buffer
 *
 * @r: The ring buffer
 *
 * Note that this function should only be called in single-consumer situations.
 */
static inline void *__mpmc_ptr_ring_peek(struct mpmc_ptr_ring *r)
{
	unsigned int c, p;
	unsigned int mask = r->mask;
	void *element;

	c = atomic_read(&r->consumer_head);

	/* Fetch consumer_head first */
	smp_rmb();

	p = atomic_read(&r->producer_tail);

	if (c == p)
		return NULL;

	/* TODO */
	smp_rmb();

	element = READ_ONCE(r->queue[c & mask]);

	return element;
}

/**
 * __mpmc_ptr_ring_discard_one - Discard the first element in an MPMC ring buffer
 *
 * @r: The ring buffer
 *
 * Note that this function should only be called in single-consumer situations.
 */
static inline void __mpmc_ptr_ring_discard_one(struct mpmc_ptr_ring *r)
{
	smp_mb__before_atomic();
	atomic_inc(&r->consumer_head);
}

#endif /* MPMC_RING_PTR_H */
