/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Thomas Gschwantner <tharre3@gmail.com>. All Rights Reserved.
 * Copyright (C) 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifdef DEBUG

#include "../mpmc_ptr_ring.h"
#include "../queueing.h"
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/wait.h>

#define THREADS_PRODUCER 20
#define THREADS_CONSUMER 20
#define ELEMENT_COUNT 100000000LL /* divisible by threads_{consumer,producer} */
#define QUEUE_SIZE 1024

#define EXPECTED_TOTAL ((ELEMENT_COUNT * (ELEMENT_COUNT + 1)) / 2)
#define PER_PRODUCER (ELEMENT_COUNT / THREADS_PRODUCER)
#define PER_CONSUMER (ELEMENT_COUNT / THREADS_CONSUMER)
#define THREADS_TOTAL (THREADS_PRODUCER + THREADS_CONSUMER)

struct worker_producer {
	struct work_struct work;
	struct workqueue_struct *wq;
	struct mpmc_ptr_ring *ring;
	uint64_t i;
	int thread_num;
};

struct worker_consumer {
	struct work_struct work;
	struct workqueue_struct *wq;
	struct mpmc_ptr_ring *ring;
	uint64_t total;
	uint64_t count;
	uint64_t i;
};

static __init void producer_function(struct work_struct *work)
{
	struct worker_producer *td = container_of(work, struct worker_producer, work);

	if (!td->i)
		td->i = td->thread_num * PER_PRODUCER + 1;

	for (; td->i <= (td->thread_num + 1) * PER_PRODUCER; ++td->i) {
		if (mpmc_ptr_ring_produce(td->ring, (void *)td->i)) {
			queue_work_on(smp_processor_id(), td->wq, work);
			return;
		}
	}
}

static __init void consumer_function(struct work_struct *work)
{
	struct worker_consumer *td = container_of(work, struct worker_consumer, work);

	for (td->i = 0; td->i < PER_CONSUMER; ++td->i) {
		uintptr_t value;
		if (!(value = (uintptr_t)mpmc_ptr_ring_consume(td->ring))) {
			queue_work_on(smp_processor_id(), td->wq, work);
			return;
		}

		td->total += value;
		++td->count;
	}
}

bool __init mpmc_ring_selftest(void)
{
	struct workqueue_struct *wq;
	struct worker_producer *producers;
	struct worker_consumer *consumers;
	struct mpmc_ptr_ring ring;
	int64_t total = 0, count = 0;
	int i;
	int cpu = 0;

	producers = kmalloc_array(THREADS_PRODUCER, sizeof(*producers), GFP_KERNEL);
	consumers = kmalloc_array(THREADS_CONSUMER, sizeof(*consumers), GFP_KERNEL);

	BUG_ON(!producers || !consumers);
	BUG_ON(mpmc_ptr_ring_init(&ring, QUEUE_SIZE, GFP_KERNEL));

	wq = alloc_workqueue("mpmc_ring_selftest", WQ_UNBOUND, 0);
	BUG_ON(!wq);

	for (i = 0; i < THREADS_PRODUCER; ++i) {
		producers[i].ring = &ring;
		producers[i].wq = wq;
		producers[i].thread_num = i;
		producers[i].i = 0;
		INIT_WORK(&producers[i].work, producer_function);
		queue_work_on(cpumask_next_online(&cpu), wq, &producers[i].work);
	}

	for (i = 0; i < THREADS_CONSUMER; ++i) {
		consumers[i].ring = &ring;
		consumers[i].wq = wq;
		consumers[i].total = 0;
		consumers[i].count = 0;
		consumers[i].i = 0;
		INIT_WORK(&consumers[i].work, consumer_function);
		queue_work_on(cpumask_next_online(&cpu), wq, &consumers[i].work);
	}

	destroy_workqueue(wq);
	BUG_ON(!mpmc_ptr_ring_empty(&ring));
	mpmc_ptr_ring_cleanup(&ring, NULL);

	for (i = 0; i < THREADS_CONSUMER; ++i) {
		total += consumers[i].total;
		count += consumers[i].count;
	}

	kfree(producers);
	kfree(consumers);

	if (count == ELEMENT_COUNT && total == EXPECTED_TOTAL) {
		pr_info("mpmc_ring self-tests: pass");
		return true;
	}

	pr_info("mpmc_ring self-test failed:");
	pr_info("Count: %llu, expected: %llu", count, ELEMENT_COUNT);
	pr_info("Total: %llu, expected: %llu", total, EXPECTED_TOTAL);

	return false;
}

#endif
