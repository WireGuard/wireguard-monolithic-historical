// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>

#include "subcommands.h"
#include "containers.h"
#include "netns.h"

const char *PROG_NAME;

static const struct {
	const char *subcommand;
	int (*function)(int, char**, struct wgoptions *);
	const char *description;
} subcommands[] = {
	{ "show", show_main, "Shows the current configuration and device information" },
	{ "showconf", showconf_main, "Shows the current configuration of a given WireGuard interface, for use with `setconf'" },
	{ "set", set_main, "Change the current configuration, add peers, remove peers, or change peers" },
	{ "setconf", setconf_main, "Applies a configuration file to a WireGuard interface" },
	{ "addconf", setconf_main, "Appends a configuration file to a WireGuard interface" },
	{ "genkey", genkey_main, "Generates a new private key and writes it to stdout" },
	{ "genpsk", genkey_main, "Generates a new preshared key and writes it to stdout" },
	{ "pubkey", pubkey_main, "Reads a private key from stdin and writes a public key to stdout" }
};

static void show_usage(FILE *file)
{
	fprintf(file, "Usage: %s <cmd> [<args>]\n\n", PROG_NAME);
	fprintf(file, "Available subcommands:\n");
	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i)
		fprintf(file, "  %s: %s\n", subcommands[i].subcommand, subcommands[i].description);
	fprintf(file, "You may pass `--help' to any of these subcommands to view usage.\n");
}

static bool parse_options(int argc, char *argv[], struct wgoptions *options)
{
	int ch;
	struct option opts[] = {
		{
			.name = "help",
			.val = 'h',
		},
		{
			.name = "netns",
			.has_arg = 1,
			.val = 'n',
		},
		{
			0
		}
	};

	setenv("POSIXLY_CORRECT", "", 0);

	while ((ch = getopt_long(argc, argv, "hn:", opts, NULL)) != -1) {
		switch (ch) {
		case '?':
			return false;
		case 'h':
			show_usage(stdout);
			exit(0);
		case 'n':
			netns_parse(&options->dev_netns, optarg);
			break;
		}
	}

	return true;
}

int main(int argc, char *argv[])
{
	struct wgoptions options = { 0 };

	PROG_NAME = argv[0];

	if (argc == 2 && !strcmp(argv[1], "help")) {
		show_usage(stdout);
		return 0;
	}

	if (!parse_options(argc, argv, &options)) {
		show_usage(stderr);
		return 1;
	}

	argv += optind;
	argc -= optind;

	if (argc == 0) {
		static char *new_argv[] = { "show", NULL };
		return show_main(1, new_argv, &options);
	}

	for (size_t i = 0; i < sizeof(subcommands) / sizeof(subcommands[0]); ++i) {
		if (!strcmp(argv[0], subcommands[i].subcommand))
			return subcommands[i].function(argc, argv, &options);
	}

	fprintf(stderr, "Invalid subcommand: `%s'\n", argv[0]);
	show_usage(stderr);
	return 1;
}
