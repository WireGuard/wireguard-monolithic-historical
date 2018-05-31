/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Jonathan Neuschäfer
 */

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

struct mpmc_ptr_ring {
	/* Read-mostly data */
	void **queue;
	size_t size;

	/* consumer_head: updated in _consume; read in _produce */
	atomic_t consumer_head ____cacheline_aligned_in_smp;

	/* producer_{head,tail}: updated in _produce */
	atomic_t producer_head ____cacheline_aligned_in_smp;
	atomic_t producer_tail;
};

static inline bool mpmc_ptr_ring_empty(struct mpmc_ptr_ring *r)
{
	size_t ptail, chead;

	/* Order the following reads against earlier stuff */
	rmb();

	ptail = atomic_read(&r->producer_tail);
	chead = atomic_read(&r->consumer_head);

	return chead == ptail;
}

static inline int mpmc_ptr_ring_produce(struct mpmc_ptr_ring *r, void *ptr)
{
	size_t p, c;
	size_t mask = r->size - 1;

	p = atomic_read(&r->producer_head);

	for (;;) {
		rmb();	 /* TODO */
		c = atomic_read(&r->consumer_head);

		if ((p - c) < mask) { /* fast path */
			if (atomic_cmpxchg(&r->producer_head, p, p + 1) == p)
				break;
		} else {
			size_t new_p;

			rmb();
			new_p = atomic_read(&r->producer_head);

			if (new_p == p)
				return -ENOSPC;

			p = new_p;
		}
	}

	WRITE_ONCE(r->queue[p & mask], ptr);

	/* Wait until it's our term to update the producer tail pointer */
	while(atomic_read(&r->producer_tail) != p)
		cpu_relax();

	/*
	 * Make sure the WRITE_ONCE above becomes visible before producer_tail
	 * is updated.
	 */
	wmb();
	atomic_set(&r->producer_tail, p + 1);

	return 0;
}

static inline void *mpmc_ptr_ring_consume(struct mpmc_ptr_ring *r)
{
	size_t c, p, old_c;
	void *element;
	size_t mask = r->size - 1;

	for (;;) {
		c = atomic_read(&r->consumer_head);

		/* Fetch consumer_head first. */
		rmb();

		p = atomic_read(&r->producer_tail);

		/* Is the ring empty? */
		if (p == c)
			return NULL;

		element = READ_ONCE(r->queue[c & mask]);

		/* TODO: Why? */
		rmb();

		old_c = atomic_cmpxchg(&r->consumer_head, c, c + 1);
		if (old_c == c)
			break;
	}

	return element;
}

/*
 * Warning: size must be greater than the number of concurrent consumers
 */
static inline int mpmc_ptr_ring_init(struct mpmc_ptr_ring *r, int size, gfp_t gfp)
{
	if (WARN_ONCE(!is_power_of_2(size), "size must be a power of two"))
		return -EINVAL;

	r->size = size;
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
	size_t c, p;
	size_t mask = r->size - 1;
	void *element;

	c = atomic_read(&r->consumer_head);

	/* Fetch consumer_head first */
	rmb();

	p = atomic_read(&r->producer_tail);

	if (c == p)
		return NULL;

	/* TODO */
	rmb();

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
