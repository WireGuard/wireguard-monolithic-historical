/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "subcommands.h"
#include "config.h"
#include "kernel.h"

int set_main(int argc, char *argv[])
{
	struct wgdevice *device = NULL;
	int ret = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s %s <interface> [listen-port <port>] [private-key <file path>] [peer <base64 public key> [remove] [endpoint <ip>:<port>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] ]...\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (!config_read_cmd(&device, argv + 2, argc - 2))
		goto cleanup;
	strncpy(device->interface, argv[1], IFNAMSIZ -  1);
	device->interface[IFNAMSIZ - 1] = 0;

	if (kernel_set_device(device) != 0) {
		perror("Unable to set device");
		goto cleanup;
	}

	ret = 0;

cleanup:
	free(device);
	return ret;
}
