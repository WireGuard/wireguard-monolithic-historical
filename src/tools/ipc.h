/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef IPC_H
#define IPC_H

#include <stdbool.h>

struct wgdevice;

int ipc_set_device(const struct wgdevice *conf);
int ipc_fetch_conf(struct wgdevice **conf, const char *interface);
char *ipc_list_devices(void);

#endif
