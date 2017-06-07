/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef WGDEVICE_H
#define WGDEVICE_H

#include "noise.h"
#include "routingtable.h"
#include "hashtables.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/net.h>

struct wireguard_device;

struct multicore_worker {
	void *ptr;
	struct work_struct work;
};

struct crypt_queue {
	spinlock_t lock;
	struct list_head queue;
	union {
		struct {
			struct multicore_worker __percpu *worker;
			int last_cpu;
		};
		struct work_struct work;
	};
	int len;
};

struct wireguard_device {
	struct net_device *dev;
	struct list_head device_list;
	struct sock __rcu *sock4, *sock6;
	u16 incoming_port;
	u32 fwmark;
	struct net *creating_net;
	struct noise_static_identity static_identity;
	struct workqueue_struct *handshake_receive_wq, *handshake_send_wq, *packet_crypt_wq;
	struct sk_buff_head incoming_handshakes;
	struct crypt_queue encrypt_queue, decrypt_queue;
	int incoming_handshake_cpu;
	struct multicore_worker __percpu *incoming_handshakes_worker;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable peer_hashtable;
	struct index_hashtable index_hashtable;
	struct routing_table peer_routing_table;
	struct list_head peer_list;
	struct mutex device_update_lock, socket_update_lock;
};

int device_init(void);
void device_uninit(void);

#endif
