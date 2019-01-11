// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#ifndef MAC_OS_X_VERSION_10_12
#define MAC_OS_X_VERSION_10_12 101200
#endif
#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12
#include <sys/random.h>
#endif
#endif

#include "curve25519.h"
#include "encoding.h"
#include "subcommands.h"

static inline ssize_t get_random_bytes(uint8_t *out, size_t len)
{
	ssize_t ret;
	int fd;

#if defined(__OpenBSD__) || (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
	ret = getentropy(out, len);
	if (!ret)
		return len;
#endif

#if defined(__NR_getrandom) && defined(__linux__)
	ret = syscall(__NR_getrandom, out, len, 0);
	if (ret >= 0)
		return ret;
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return fd;
	ret = read(fd, out, len);
	close(fd);
	return ret;
}

int genkey_main(int argc, char *argv[])
{
	uint8_t key[WG_KEY_LEN];
	char base64[WG_KEY_LEN_BASE64];
	struct stat stat;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (!fstat(STDOUT_FILENO, &stat) && S_ISREG(stat.st_mode) && stat.st_mode & S_IRWXO)
		fputs("Warning: writing to world accessible file.\nConsider setting the umask to 077 and trying again.\n", stderr);

	if (get_random_bytes(key, WG_KEY_LEN) != WG_KEY_LEN) {
		perror("getrandom");
		return 1;
	}
	if (!strcmp(argv[0], "genkey"))
		curve25519_clamp_secret(key);

	key_to_base64(base64, key);
	puts(base64);
	return 0;
}
