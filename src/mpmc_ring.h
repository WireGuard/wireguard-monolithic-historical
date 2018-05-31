/*
 * Copyright 2009-2015 Samy Al Bahra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef MPMC_RING_H
#define MPMC_RING_H

#include <stdbool.h>
#include <linux/string.h>

#include <linux/processor.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/cache.h>

/* http://concurrencykit.org/doc/ck_pr_fence_store_atomic.html */
/* this actually resolves to __asm__ __volatile__("" ::: "memory"); in x86-64 */
/* so basically a compiler barrier? */
#define ck_pr_fence_store_atomic() smp_mb__before_atomic() /* TODO: probably overkill? */

/*
 * Concurrent ring buffer.
 */

struct ck_ring {
	atomic_t c_head ____cacheline_aligned_in_smp;
	atomic_t p_tail ____cacheline_aligned_in_smp;
	atomic_t p_head;
	unsigned int size ____cacheline_aligned_in_smp;
	unsigned int mask;
	void **queue;
};
typedef struct ck_ring ck_ring_t;

static inline int ck_ring_init(struct ck_ring *ring, uint size, gfp_t gfp)
{
	ring->size = size;
	ring->mask = size - 1;
	atomic_set(&ring->p_tail, 0);
	atomic_set(&ring->p_head, 0); // TODO: barrier?
	atomic_set(&ring->c_head, 0);

	ring->queue = kcalloc(size, sizeof(void *), gfp);
	if (!ring->queue)
		return -ENOMEM;

	return 0;
}

__always_inline static bool
_ck_ring_enqueue_mp(struct ck_ring *ring, const void *entry, unsigned int ts,
    unsigned int *size)
{
	const unsigned int mask = ring->mask;
	unsigned int producer, consumer, delta;
	void *buffer;
	bool r = true;

	producer = atomic_read(&ring->p_head);

	for (;;) {
		/*
		 * The snapshot of producer must be up to date with respect to
		 * consumer.
		 */
		smp_rmb();
		consumer = atomic_read(&ring->c_head);

		delta = (producer + 1) & mask;

		/*
		 * Only try to CAS if the producer is not clearly stale (not
		 * less than consumer) and the buffer is definitely not full.
		 */
		if (likely((producer - consumer) < mask)) {
			if (atomic_cmpxchg(&ring->p_head, producer, delta) == producer)
				break;

			producer = delta;
		} else {
			unsigned int new_producer;

			/*
			 * Slow path.  Either the buffer is full or we have a
			 * stale snapshot of p_head.  Execute a second read of
			 * p_read that must be ordered wrt the snapshot of
			 * c_head.
			 */
			smp_rmb();
			new_producer = atomic_read(&ring->p_head);

			/*
			 * Only fail if we haven't made forward progress in
			 * production: the buffer must have been full when we
			 * read new_producer (or we wrapped around UINT_MAX
			 * during this iteration).
			 */
			if (producer == new_producer) {
				r = false;
				goto leave;
			}

			/*
			 * p_head advanced during this iteration. Try again.
			 */
			producer = new_producer;
		}
	}

	buffer = (char *)ring->queue + ts * producer;
	memcpy(buffer, entry, ts);

	/*
	 * Wait until all concurrent producers have completed writing
	 * their data into the ring buffer.
	 */
	while (atomic_read(&ring->p_tail) != producer)
		cpu_relax();

	/*
	 * Ensure that copy is completed before updating shared producer
	 * counter.
	 */
	smp_wmb();
	atomic_set(&ring->p_tail, delta);

leave:
	if (size != NULL)
		*size = (producer - consumer) & mask;

	return r;
}

__always_inline static bool
_ck_ring_enqueue_mp_size(struct ck_ring *ring, const void *entry,
    unsigned int ts, unsigned int *size)
{
	unsigned int sz;
	bool r;

	r = _ck_ring_enqueue_mp(ring, entry, ts, &sz);
	*size = sz;
	return r;
}

__always_inline static bool
_ck_ring_trydequeue_mc(struct ck_ring *ring,
    void *data, unsigned int size)
{
	const unsigned int mask = ring->mask;
	unsigned int consumer, producer;
	const void *buffer;

	consumer = atomic_read(&ring->c_head);
	smp_rmb();
	producer = atomic_read(&ring->p_tail);

	if (unlikely(consumer == producer))
		return false;

	smp_rmb();

	buffer = (const char *)ring->queue + size * consumer;
	memcpy(data, buffer, size);

	ck_pr_fence_store_atomic();
	return atomic_cmpxchg(&ring->c_head, consumer, (consumer + 1) & mask) == consumer;
}

__always_inline static bool
_ck_ring_dequeue_mc(struct ck_ring *ring,
    void *data, unsigned int ts)
{
	const unsigned int mask = ring->mask;
	unsigned int consumer, producer, delta;
	bool cmp;

	consumer = atomic_read(&ring->c_head);

	do {
		const char *target;

		/*
		 * Producer counter must represent state relative to
		 * our latest consumer snapshot.
		 */
		smp_rmb();
		producer = atomic_read(&ring->p_tail);

		if (unlikely(consumer == producer))
			return false;

		smp_rmb();

		target = (const char *)ring->queue + ts * consumer;
		memcpy(data, target, ts);

		/* Serialize load with respect to head update. */
		ck_pr_fence_store_atomic();

		delta = (consumer + 1) & mask;
		cmp = atomic_cmpxchg(&ring->c_head, consumer, delta) == consumer;
		consumer = delta;
	} while (!cmp);

	return true;
}

__always_inline static bool
_ck_ring_enqueue_sp(struct ck_ring *ring, const void *entry,
    unsigned int ts,
    unsigned int *size)
{
	const unsigned int mask = ring->mask;
	unsigned int consumer, producer, delta;
	void *buffer;

	consumer = atomic_read(&ring->c_head);
	producer = atomic_read(&ring->p_tail);
	delta = producer + 1;
	if (size != NULL)
		*size = (producer - consumer) & mask;

	if (unlikely((delta & mask) == (consumer & mask)))
		return false;

	buffer = (char *)buffer + ts * (producer & mask);
	memcpy(buffer, entry, ts);

	/*
	 * Make sure to update slot value before indicating
	 * that the slot is available for consumption.
	 */
	smp_wmb();
	atomic_set(&ring->p_tail, delta);
	return true;
}

__always_inline static bool
_ck_ring_enqueue_sp_size(struct ck_ring *ring,
    const void *entry,
    unsigned int ts,
    unsigned int *size)
{
	unsigned int sz;
	bool r;

	r = _ck_ring_enqueue_sp(ring, entry, ts, &sz);
	*size = sz;
	return r;
}

__always_inline static bool
_ck_ring_dequeue_sc(struct ck_ring *ring,
    void *target,
    unsigned int size)
{
	const unsigned int mask = ring->mask;
	unsigned int consumer, producer;
	const void *buffer;

	consumer = atomic_read(&ring->c_head);
	producer = atomic_read(&ring->p_tail);

	if (unlikely(consumer == producer))
		return false;

	/*
	 * Make sure to serialize with respect to our snapshot
	 * of the producer counter.
	 */
	smp_rmb();

	buffer = (const char *)buffer + size * (consumer & mask);
	memcpy(target, buffer, size);

	/*
	 * Make sure copy is completed with respect to consumer
	 * update.
	 */
	smp_wmb();
	atomic_set(&ring->c_head, consumer + 1);
	return true;
}

static __always_inline bool mpmc_ring_empty(struct ck_ring *ring)
{
	uint producer, consumer;

	consumer = atomic_read(&ring->c_head);
	smp_rmb();
	producer = atomic_read(&ring->p_tail);

	smp_rmb();

	return producer == consumer;
}

static __always_inline void mpmc_ring_cleanup(struct ck_ring *ring)
{
	kfree(ring->queue);
}

static __always_inline bool mpmc_ptr_ring_peek(struct ck_ring *ring, void *data,
		uint size)
{
	uint producer, consumer;
	const unsigned int mask = ring->mask;
	void *buffer;

	consumer = atomic_read(&ring->c_head);
	smp_rmb();
	producer = atomic_read(&ring->p_tail);

	smp_rmb();

	if (unlikely(producer == consumer)) {
		data = NULL;
		return false;
	}

	buffer = (char *)ring->queue + size * (consumer & mask);
	memcpy(data, buffer, size);

	return true;
}

static __always_inline void mpmc_ptr_ring_discard(struct ck_ring *ring)
{
	const unsigned int mask = ring->mask;
	unsigned int consumer = atomic_read(&ring->c_head);

	atomic_set(&ring->c_head, (consumer + 1) & mask);
}

/*
 * The ck_ring_*_mpmc namespace is the public interface for interacting with a
 * ring buffer containing pointers. Correctness is provided for any number of
 * producers and consumers.
 */
inline static bool
ck_ring_enqueue_mpmc(struct ck_ring *ring, const void *entry)
{
	return _ck_ring_enqueue_mp(ring, &entry, sizeof(entry), NULL);
}

inline static bool
ck_ring_enqueue_mpmc_size(struct ck_ring *ring, const void *entry,
    unsigned int *size)
{
	return _ck_ring_enqueue_mp_size(ring, &entry, sizeof(entry), size);
}

inline static bool
ck_ring_trydequeue_mpmc(struct ck_ring *ring, void *data)
{
	return _ck_ring_trydequeue_mc(ring, (void **)data, sizeof(void *));
}

inline static bool
ck_ring_dequeue_mpmc(struct ck_ring *ring, void *data)
{
	return _ck_ring_dequeue_mc(ring, (void **)data, sizeof(void *));
}

#endif /* _WG_MPMC_RING_H */
