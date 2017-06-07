/* Copyright (C) 2017 Samuel Holland <samuel@sholland.org>. All Rights Reserved. */

#ifndef WGQUEUE_H
#define WGQUEUE_H

#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "device.h"
#include "peer.h"

#define QUEUE_MAX_LEN 1000

enum {
	CTX_NEW,
	CTX_FINISHED,
	CTX_FREEING,
};

struct crypt_ctx {
	struct list_head peer_list;
	struct list_head shared_list;
	union {
		struct sk_buff_head packets;
		struct sk_buff *skb;
	};
	struct wireguard_peer *peer;
	struct noise_keypair *keypair;
	struct endpoint endpoint;
	atomic_t state;
};

static inline int next_cpu(int *next)
{
	int cpu = *next;

	if (cpu >= nr_cpumask_bits || !cpumask_test_cpu(cpu, cpu_online_mask))
		cpu = cpumask_first(cpu_online_mask);
	*next = cpumask_next(cpu, cpu_online_mask);
	return cpu;
}

/**
 * __queue_dequeue - Atomically remove the first item in a queue.
 *
 * @return The address of the dequeued item, or NULL if the queue is empty.
 *
 * This function is safe to execute concurrently with any number of
 * __queue_enqueue() calls, but *not* with another __queue_dequeue() call
 * operating on the same queue.
 */
static inline struct list_head *__queue_dequeue(struct list_head *queue)
{
	struct list_head *first, *second;

	first = READ_ONCE(queue->next);
	if (first == queue)
		return NULL;
	do {
		second = READ_ONCE(first->next);
		WRITE_ONCE(queue->next, second);
	} while (cmpxchg(&second->prev, first, queue) != first);
	return first;
}

static inline struct list_head *queue_dequeue(struct crypt_queue *queue)
{
	struct list_head *head = __queue_dequeue(&queue->list);
	if (head)
		atomic_dec(&queue->qlen);
	return head;
}

#define queue_dequeue_peer(queue) ({ \
	struct list_head *__head = queue_dequeue(queue); \
	__head ? list_entry(__head, struct crypt_ctx, peer_list) : NULL; \
})

#define queue_dequeue_shared(queue) ({ \
	struct list_head *__head = queue_dequeue(queue); \
	__head ? list_entry(__head, struct crypt_ctx, shared_list) : NULL; \
})

#define queue_empty(queue) \
	list_empty(&(queue)->list)

/**
 * __queue_enqueue - Atomically append an item to the tail of a queue.
 *
 * This function is safe to execute concurrently with any number of other
 * __queue_enqueue() calls, as well as with one __queue_dequeue() call
 * operating on the same queue.
 */
static inline void __queue_enqueue(struct list_head *queue,
				   struct list_head *head)
{
	struct list_head *last;

	WRITE_ONCE(head->next, queue);
	do {
		last = READ_ONCE(queue->prev);
		WRITE_ONCE(head->prev, last);
	} while (cmpxchg(&queue->prev, last, head) != last);
	WRITE_ONCE(last->next, head);
}

static inline bool queue_enqueue(struct crypt_queue *queue,
				 struct list_head *head,
				 int limit)
{
	bool have_space = !limit || atomic_inc_return(&queue->qlen) <= limit;
	if (have_space)
		__queue_enqueue(&queue->list, head);
	else
		atomic_dec(&queue->qlen);
	return have_space;
}

#define queue_enqueue_peer(queue, ctx) \
	queue_enqueue(queue, &(ctx)->peer_list, QUEUE_MAX_LEN)

#define queue_enqueue_shared(queue, ctx, wq, cpu) ({ \
	int __cpu = next_cpu(cpu); \
	struct crypt_queue *__queue = per_cpu_ptr(queue, __cpu); \
	queue_enqueue(__queue, &(ctx)->shared_list, 0); \
	queue_work_on(__cpu, wq, &__queue->work); \
	true; \
})

#define queue_first_peer(queue) \
	list_first_entry_or_null(&(queue)->list, struct crypt_ctx, peer_list)

#define queue_first_shared(queue) \
	list_first_entry_or_null(&(queue)->list, struct crypt_ctx, shared_list)

#define queue_full(queue) \
	(atomic_read(&(queue)->qlen) == QUEUE_MAX_LEN)

#endif /* WGQUEUE_H */
