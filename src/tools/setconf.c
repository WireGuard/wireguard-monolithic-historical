/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "containers.h"
#include "config.h"
#include "ipc.h"
#include "subcommands.h"

int setconf_main(int argc, char *argv[])
{
	struct wgdevice *device = NULL;
	struct config_ctx ctx;
	FILE *config_input = NULL;
	char *config_buffer = NULL;
	size_t config_buffer_len = 0;
	int ret = 1;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s %s <interface> <configuration filename>\n", PROG_NAME, argv[0]);
		return 1;
	}

	config_input = fopen(argv[2], "r");
	if (!config_input) {
		perror("fopen");
		return 1;
	}
	if (!config_read_init(&ctx, !strcmp(argv[0], "addconf"))) {
		fclose(config_input);
		return 1;
	}
	while (getline(&config_buffer, &config_buffer_len, config_input) >= 0) {
		if (!config_read_line(&ctx, config_buffer)) {
			fprintf(stderr, "Configuration parsing error\n");
			goto cleanup;
		}
	}
	device = config_read_finish(&ctx);
	if (!device) {
		fprintf(stderr, "Invalid configuration\n");
		goto cleanup;
	}
	strncpy(device->name, argv[1], IFNAMSIZ - 1);
	device->name[IFNAMSIZ - 1] = '\0';

	if (ipc_set_device(device) != 0) {
		perror("Unable to set device");
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (config_input)
		fclose(config_input);
	free(config_buffer);
	free_wgdevice(device);
	return ret;
}
