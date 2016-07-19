/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef KERNEL_H
#define KERNEL_H

#include <stdbool.h>

struct wgdevice;

int set_device(struct wgdevice *dev);
int get_device(struct wgdevice **dev, const char *interface);
char *get_wireguard_interfaces(void);
bool has_wireguard_interface(const char *interface);


#define for_each_wgpeer(__dev, __peer, __i) for ((__i) = 0, (__peer) = (typeof(__peer))((uint8_t *)(__dev) + sizeof(struct wgdevice)); \
						 (__i) < (__dev)->num_peers; \
						 ++(__i), (__peer) = (typeof(__peer))((uint8_t *)(__peer) + sizeof(struct wgpeer) + (sizeof(struct wgipmask) * (__peer)->num_ipmasks)))

#define for_each_wgipmask(__peer, __ipmask, __i) for ((__i) = 0, (__ipmask) = (typeof(__ipmask))((uint8_t *)(__peer) + sizeof(struct wgpeer)); \
						 (__i) < (__peer)->num_ipmasks; \
						 ++(__i), (__ipmask) = (typeof(__ipmask))((uint8_t *)(__ipmask) + sizeof(struct wgipmask)))

#endif
