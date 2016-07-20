/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef IPC_H
#define IPC_H

#include <stdbool.h>

struct wgdevice;

int ipc_set_device(struct wgdevice *dev);
int ipc_get_device(struct wgdevice **dev, const char *interface);
char *ipc_list_devices(void);
bool ipc_has_device(const char *interface);


#define for_each_wgpeer(__dev, __peer, __i) for ((__i) = 0, (__peer) = (typeof(__peer))((uint8_t *)(__dev) + sizeof(struct wgdevice)); \
						 (__i) < (__dev)->num_peers; \
						 ++(__i), (__peer) = (typeof(__peer))((uint8_t *)(__peer) + sizeof(struct wgpeer) + (sizeof(struct wgipmask) * (__peer)->num_ipmasks)))

#define for_each_wgipmask(__peer, __ipmask, __i) for ((__i) = 0, (__ipmask) = (typeof(__ipmask))((uint8_t *)(__peer) + sizeof(struct wgpeer)); \
						 (__i) < (__peer)->num_ipmasks; \
						 ++(__i), (__ipmask) = (typeof(__ipmask))((uint8_t *)(__ipmask) + sizeof(struct wgipmask)))

#endif
