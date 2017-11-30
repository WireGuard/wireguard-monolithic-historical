/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

static bool color_mode(FILE *file)
{
	static int mode = -1;
	const char *var;

	if (mode != -1)
		return mode;
	var = getenv("WG_COLOR_MODE");
	if (var && !strcmp(var, "always"))
		mode = true;
	else if (var && !strcmp(var, "never"))
		mode = false;
	else
		return isatty(fileno(file));
	return mode;
}

static void filter_ansi(FILE *file, const char *fmt, va_list args)
{
	char *str = NULL;
	size_t len, i, j;

	if (color_mode(file)) {
		vfprintf(file, fmt, args);
		return;
	}

	len = vasprintf(&str, fmt, args);

	if (len >= 2) {
		for (i = 0; i < len - 2; ++i) {
			if (str[i] == '\x1b' && str[i + 1] == '[') {
				str[i] = str[i + 1] = '\0';
				for (j = i + 2; j < len; ++j) {
					if (isalpha(str[j]))
						break;
					str[j] = '\0';
				}
				str[j] = '\0';
			}
		}
	}
	for (i = 0; i < len; i = j) {
		fputs(&str[i], file);
		for (j = i + strlen(&str[i]); j < len; ++j) {
			if (str[j] != '\0')
				break;
		}
	}

	free(str);
}

void terminal_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	filter_ansi(stdout, fmt, args);
	va_end(args);
}

void terminal_fprintf(FILE *file, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	filter_ansi(file, fmt, args);
	va_end(args);
}
