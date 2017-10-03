/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "queueing.h"
#include <linux/slab.h>

struct kmem_cache *crypt_ctx_cache __read_mostly;

struct multicore_worker __percpu *packet_alloc_percpu_multicore_worker(work_func_t function, void *ptr)
{
	int cpu;
	struct multicore_worker __percpu *worker = alloc_percpu(struct multicore_worker);

	if (!worker)
		return NULL;

	for_each_possible_cpu (cpu) {
		per_cpu_ptr(worker, cpu)->ptr = ptr;
		INIT_WORK(&per_cpu_ptr(worker, cpu)->work, function);
	}
	return worker;
}

int packet_queue_init(struct crypt_queue *queue, work_func_t function, bool multicore)
{
	INIT_LIST_HEAD(&queue->queue);
	queue->len = 0;
	spin_lock_init(&queue->lock);
	if (multicore) {
		queue->worker = packet_alloc_percpu_multicore_worker(function, queue);
		if (!queue->worker)
			return -ENOMEM;
	} else
		INIT_WORK(&queue->work, function);
	return 0;
}

int __init crypt_ctx_cache_init(void)
{
	crypt_ctx_cache = KMEM_CACHE(crypt_ctx, 0);
	if (!crypt_ctx_cache)
		return -ENOMEM;
	return 0;
}

void crypt_ctx_cache_uninit(void)
{
	kmem_cache_destroy(crypt_ctx_cache);
}
