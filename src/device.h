/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

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
#include <linux/padata.h>

struct wireguard_device {
	struct sock __rcu *sock4, *sock6;
	u16 incoming_port;
	struct net *creating_net;
	struct workqueue_struct *workqueue;
	struct workqueue_struct *parallelqueue;
	struct padata_instance *parallel_send, *parallel_receive;
	struct noise_static_identity static_identity;
	struct sk_buff_head incoming_handshakes;
	struct work_struct incoming_handshakes_work;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable peer_hashtable;
	struct index_hashtable index_hashtable;
	struct routing_table peer_routing_table;
	struct list_head peer_list;
	struct mutex device_update_lock;
	struct mutex socket_update_lock;
};

int device_init(void);
void device_uninit(void);

#endif
