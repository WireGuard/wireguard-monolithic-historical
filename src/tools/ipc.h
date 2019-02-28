/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef IPC_H
#define IPC_H

#include <stdbool.h>

struct wgdevice;

int ipc_set_device(const struct wgdevice *conf);

/**
 * Fetch wireguard device configuration
 *
 * Fetch wireguard device configuration from kernel through Netlink socket (or through
 * different IPC methods from the userspace daemon process)
 *
 * @param interface - the interface name
 * @param conf - the output configuration pointer pointing to an allocated memory
 *               block which should be freed later by free_conf()
 * @return 0 on success, negetive on errors. This func should never return positive integer.
 * @see free_conf()
 */
int ipc_fetch_conf(struct wgdevice **conf, const char *interface);

/**
 * Free the memory block allocated by ipc_fetch_conf()
 *
 * free_conf() is an alias of free_wgdevice()
 * @param conf - the pointer that pointing to allocated memory block
 * @see ipc_fetch_conf()
 */
void free_conf(struct wgdevice *conf);

char *ipc_list_devices(void);

#endif
