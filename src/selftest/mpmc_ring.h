/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Thomas Gschwantner <tharre3@gmail.com>. All Rights Reserved.
 */

#ifdef DEBUG

#include "../mpmc_ptr_ring.h"
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/wait.h>

#define THREADS_PRODUCER 2
#define THREADS_CONSUMER 2
#define ELEMENT_COUNT 100000000LL /* divisible by threads_{consumer,producer} */
#define QUEUE_SIZE 1024

#define EXPECTED_TOTAL ((ELEMENT_COUNT * (ELEMENT_COUNT + 1)) / 2)
#define PER_PRODUCER (ELEMENT_COUNT/THREADS_PRODUCER)
#define PER_CONSUMER (ELEMENT_COUNT/THREADS_CONSUMER)
#define THREADS_TOTAL (THREADS_PRODUCER + THREADS_CONSUMER)

struct mpmc_ptr_ring *ring __initdata;

struct worker_producer {
	struct work_struct work;
	int thread_num;
};

struct worker_consumer {
	struct work_struct work;
	int thread_num;
	int64_t total;
	int64_t count;
};

static __init void producer_function(struct work_struct *work)
{
	struct worker_producer *td = container_of(work, struct worker_producer, work);
	uintptr_t count = (td->thread_num * PER_PRODUCER) + 1;

	for (; count <= (td->thread_num + 1) * PER_PRODUCER; ++count) {
		while (mpmc_ptr_ring_produce(ring, (void *) count)) {
			schedule();
			/*pr_info("We have awoken (producer)");*/
		}
	}
}

static __init void consumer_function(struct work_struct *work)
{
	struct worker_consumer *td = container_of(work, struct worker_consumer, work);
	int i;

	for (i = 0; i < PER_CONSUMER; ++i) {
		uintptr_t value;
		while (!(value = (uintptr_t) mpmc_ptr_ring_consume(ring))) {
			schedule();
			/*cpu_relax();*/
			/*pr_info("We have awoken (consumer)");*/
		}

		td->total += value;
		++(td->count);
	}
}

bool __init mpmc_ring_selftest(void)
{
	struct workqueue_struct *wq;
	struct worker_producer *producers;
	struct worker_consumer *consumers;
	int64_t total = 0, count = 0;
	int i;

	producers = kmalloc_array(THREADS_PRODUCER, sizeof(*producers), GFP_KERNEL);
	consumers = kmalloc_array(THREADS_CONSUMER, sizeof(*consumers), GFP_KERNEL);
	ring = kmalloc(sizeof(*ring), GFP_KERNEL);

	BUG_ON(!ring || !producers || !consumers);
	BUG_ON(mpmc_ptr_ring_init(ring, QUEUE_SIZE, GFP_KERNEL));

	wq = alloc_workqueue("mpmc_ring_selftest", WQ_UNBOUND, 0);

	for (i = 0; i < THREADS_PRODUCER; ++i) {
		producers[i].thread_num = i;
		INIT_WORK(&producers[i].work, producer_function);
		queue_work(wq, &producers[i].work);
	}

	for (i = 0; i < THREADS_CONSUMER; ++i) {
		consumers[i] = (struct worker_consumer) {
			.thread_num = i,
			.total = 0,
			.count = 0,
		};
		INIT_WORK(&consumers[i].work, consumer_function);
		queue_work(wq, &consumers[i].work);
	}

	destroy_workqueue(wq);
	BUG_ON(!mpmc_ptr_ring_empty(ring));
	mpmc_ptr_ring_cleanup(ring, NULL);
	kfree(ring);

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
	pr_info("Count: %lld, expected: %lld", count, ELEMENT_COUNT);
	pr_info("Total: %lld, expected: %lld", total, EXPECTED_TOTAL);

	return false;
}

#endif
