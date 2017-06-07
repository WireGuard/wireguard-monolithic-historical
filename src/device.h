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
struct handshake_worker {
	struct wireguard_device *wg;
	struct work_struct work;
};

struct crypt_queue {
	struct list_head list;
	struct work_struct work;
	atomic_t qlen;
};

struct wireguard_device {
	struct net_device *dev;
	struct list_head device_list;
	struct sock __rcu *sock4, *sock6;
	u16 incoming_port;
	u32 fwmark;
	struct net *creating_net;
	struct noise_static_identity static_identity;
	struct workqueue_struct *incoming_handshake_wq, *peer_wq;
	struct sk_buff_head incoming_handshakes;
	atomic_t incoming_handshake_seqnr;
	struct handshake_worker __percpu *incoming_handshakes_worker;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable peer_hashtable;
	struct index_hashtable index_hashtable;
	struct routing_table peer_routing_table;
	struct list_head peer_list;
	struct mutex device_update_lock;
	struct mutex socket_update_lock;
	struct workqueue_struct *crypt_wq;
	int encrypt_cpu, decrypt_cpu;
	struct crypt_queue __percpu *encrypt_queue, *decrypt_queue;
};

int device_init(void);
void device_uninit(void);

#endif
