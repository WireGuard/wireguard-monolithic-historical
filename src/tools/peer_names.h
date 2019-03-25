// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Luis Ressel <aranea@aixah.de>. All Rights Reserved.
 */

#ifndef PEER_NAMES_H
#define PEER_NAMES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "containers.h"

struct wgpeer_name {
	char *name;
	uint8_t public_key[WG_KEY_LEN];
};

struct wgpeer_names {
	size_t len;
	struct wgpeer_name *arr;
};

bool peer_names_open(struct wgpeer_names *names, struct wgdevice *device);
void peer_names_free(struct wgpeer_names *names);
char *peer_names_get(struct wgpeer_names *names, uint8_t key[static WG_KEY_LEN]);

#endif // PEER_NAMES_H
