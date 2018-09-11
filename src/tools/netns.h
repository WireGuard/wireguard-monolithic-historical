/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Julian orth <ju.orth@gmail.com>. All Rights Reserved.
 */

#ifndef NETNS_H
#define NETNS_H

#include <stdbool.h>

#include "containers.h"

bool netns_enter(struct wgnetns *netns);
bool netns_parse(struct wgnetns *netns, const char *arg);

extern struct wgnetns netns_current;

#endif
