/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef WGCONFIG_H
#define WGCONFIG_H

struct wireguard_device;

int config_get_device(struct wireguard_device *wg, void __user *udevice);
int config_set_device(struct wireguard_device *wg, void __user *udevice);

#endif
