/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef SUBCOMMANDS_H
#define SUBCOMMANDS_H

#include "containers.h"

extern const char *PROG_NAME;
int show_main(int argc, char *argv[], struct wgoptions *);
int showconf_main(int argc, char *argv[], struct wgoptions *);
int set_main(int argc, char *argv[], struct wgoptions *);
int setconf_main(int argc, char *argv[], struct wgoptions *);
int genkey_main(int argc, char *argv[], struct wgoptions *);
int pubkey_main(int argc, char *argv[], struct wgoptions *);

#endif
