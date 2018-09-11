/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Julian orth <ju.orth@gmail.com>. All Rights Reserved.
 */

#include <fcntl.h>
#include <stdio.h>
#include <sched.h>
#include <ctype.h>

#include "netns.h"

struct wgnetns netns_current = { 0 };

bool netns_enter(struct wgnetns *netns)
{
	int fd = netns->fd;

	if (!netns->flags)
		return true;

	if (netns->flags & WGNETNS_HAS_PID) {
		char path[64];
		sprintf(path, "/proc/%d/ns/net", netns->pid);
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			perror("Unable to open netns by pid");
			return false;
		}
	}

	if (setns(fd, CLONE_NEWNET)) {
		perror("setns");
		return false;
	}

	return true;
}

bool netns_parse(struct wgnetns *netns, const char *arg)
{
	/* U32 arg -> PID */
	if (isdigit(*arg)) {
		char *end;
		unsigned long pid = strtoul(arg, &end, 10);
		if (!*end && pid <= UINT32_MAX) {
			netns->pid = pid;
			netns->flags |= WGNETNS_HAS_PID;
			return true;
		}
	}

	/* Otherwise -> file path */
	netns->fd = open(arg, O_RDONLY);
	if (netns->fd >= 0) {
		netns->flags |= WGNETNS_HAS_FD;
		return true;
	}

	perror("open");
	return false;
}
