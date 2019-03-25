// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Luis Ressel <aranea@aixah.de>. All Rights Reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "containers.h"
#include "encoding.h"
#include "peer_names.h"

static bool parse_peer_name(char *line, struct wgpeer_name *slot)
{
	char *name;
	size_t len;

	name = strpbrk(line, " \t");
	if (!name)
		return false;
	*name = '\0';

	if (!key_from_base64(slot->public_key, line))
		return false;

	len = strlen(++name);
	if (name[len - 1] == '\n')
		name[len - 1] = '\0';
	slot->name = strdup(name);
	return !!slot->name;
}

static int peer_name_cmp(const void *a, const void *b)
{
	const struct wgpeer_name *x = a, *y = b;
	return memcmp(x->public_key, y->public_key, WG_KEY_LEN);
}

bool peer_names_open(struct wgpeer_names *names, struct wgdevice *device)
{
	size_t max_peers = 1, peers = 0, buf_len = 0, path_len;
	struct wgpeer_name *arr, *arr2;
	char *buf = NULL, *path;
	FILE *f;

	path = getenv("WG_PEER_NAMES");
	if (!path || !path[0]) {
		errno = 0;
		return false;
	}

	path_len = strlen(path);
	if (path[path_len - 1] == '/') {
		size_t dev_len = strlen(device->name);
		char *path2 = malloc(path_len + dev_len + 1);

		if (!path2)
			return false;
		memcpy(path2, path, path_len);
		memcpy(path2 + path_len, device->name, dev_len + 1);
		f = fopen(path2, "r");
		free(path2);
	} else
		f = fopen(path, "r");
	if (!f)
		return false;

	arr = malloc(sizeof(struct wgpeer_name));
	if (!arr)
		return false;

	while (getline(&buf, &buf_len, f) >= 0) {
		if (parse_peer_name(buf, &arr[peers]) && (++peers == max_peers)) {
			// TODO: Pulled this overflow check out of my ass, gotta revisit it later
			if (SIZE_MAX / (2 * sizeof(struct wgpeer_name)) < max_peers) {
				errno = ENOMEM;
				return false;
			}
			max_peers *= 2;

			arr2 = realloc(arr, max_peers * sizeof(struct wgpeer_name));
			if (!arr2) {
				free(arr);
				return false;
			}
			arr = arr2;
		}
	}
	free(buf);

	if (!peers)
		free(arr);
	if ((arr2 = realloc(arr, peers * sizeof(struct wgpeer_name))))
		arr = arr2;

	qsort(arr, peers, sizeof(struct wgpeer_name), peer_name_cmp);
	names->len = peers;
	names->arr = arr;
	return true;
}

void peer_names_free(struct wgpeer_names *names)
{
	if (!names)
		return;

	for (size_t i = 0; i < names->len; ++i)
		free(names->arr[i].name);
	if (names->len)
		free(names->arr);
}

char *peer_names_get(struct wgpeer_names *names, uint8_t key[static WG_KEY_LEN])
{
	size_t r, l = 0;

	if (!names || !names->len)
		return NULL;
	r = names->len - 1;

	while (l <= r) {
		size_t m = l + (r - l) / 2;
		int cmp = memcmp(key, names->arr[m].public_key, WG_KEY_LEN);
		if (!cmp)
			return names->arr[m].name;
		else if (cmp > 0)
			l = m + 1;
		else if (!m)
			break;
		else
			r = m - 1;
	}
	return NULL;
}
