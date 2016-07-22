/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef IPC_H
#define IPC_H

#include <stdbool.h>

struct wgdevice;

int ipc_set_device(struct wgdevice *dev);
int ipc_get_device(struct wgdevice **dev, const char *interface);
char *ipc_list_devices(void);
bool ipc_has_device(const char *interface);

#endif
