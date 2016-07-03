/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>
#include <string.h>

#include "curve25519.h"
#include "base64.h"
#include "subcommands.h"

#ifdef __NR_getrandom
static inline ssize_t get_random_bytes(uint8_t *out, size_t len)
{
	return syscall(__NR_getrandom, out, len, 0);
}
#else
#include <fcntl.h>
static inline ssize_t get_random_bytes(uint8_t *out, size_t len)
{
	ssize_t ret;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return fd;
	ret = read(fd, out, len);
	close(fd);
	return ret;
}
#endif

int genkey_main(int argc, char *argv[])
{
	unsigned char private_key[CURVE25519_POINT_SIZE];
	char private_key_base64[b64_len(CURVE25519_POINT_SIZE)];
	struct stat stat;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (!fstat(STDOUT_FILENO, &stat) && S_ISREG(stat.st_mode) && stat.st_mode & S_IRWXO)
		fputs("Warning: writing to world accessible file.\nConsider setting the umask to 077 and trying again.\n", stderr);

	if (get_random_bytes(private_key, CURVE25519_POINT_SIZE) != CURVE25519_POINT_SIZE) {
		perror("getrandom");
		return 1;
	}
	if (argc && !strcmp(argv[0], "genkey"))
		curve25519_normalize_secret(private_key);

	if (b64_ntop(private_key, sizeof(private_key), private_key_base64, sizeof(private_key_base64)) != sizeof(private_key_base64) - 1) {
		fprintf(stderr, "%s: Could not convert key to base64\n", PROG_NAME);
		return 1;
	}

	puts(private_key_base64);
	return 0;

}
