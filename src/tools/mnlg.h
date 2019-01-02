/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Original author: Jiri Pirko <jiri@mellanox.com>
 */

#ifndef MNLG_H
#define MNLG_H
#ifdef __linux__

#include <libmnl/libmnl.h>

struct mnlg_socket;

struct nlmsghdr *mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
				  uint16_t flags);
int mnlg_socket_send(struct mnlg_socket *nlg, const struct nlmsghdr *nlh);
int mnlg_socket_recv_run(struct mnlg_socket *nlg, mnl_cb_t data_cb, void *data);
int mnlg_socket_group_add(struct mnlg_socket *nlg, const char *group_name);
struct mnlg_socket *mnlg_socket_open(const char *family_name, uint8_t version);
void mnlg_socket_close(struct mnlg_socket *nlg);

#endif
#endif
