/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../uapi.h"

struct inflatable_device {
	struct wgdevice *dev;
	size_t len;
	size_t pos;
};

struct config_ctx {
	struct inflatable_device buf;
	size_t peer_offset;
	struct wgdevice **device;
	bool is_peer_section;
	bool is_device_section;
};

bool config_read_cmd(struct wgdevice **dev, char *argv[], int argc);
bool config_read_init(struct config_ctx *ctx, struct wgdevice **device, bool append);
bool config_read_line(struct config_ctx *ctx, const char *line);
bool config_read_finish(struct config_ctx *ctx);

#endif
