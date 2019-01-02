// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Original author: Jiri Pirko <jiri@mellanox.com>
 */

#ifdef __linux__

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <libmnl/libmnl.h>
#include <linux/genetlink.h>

#include "mnlg.h"

struct mnlg_socket {
	struct mnl_socket *nl;
	char *buf;
	uint16_t id;
	uint8_t version;
	unsigned int seq;
	unsigned int portid;
};

static struct nlmsghdr *__mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
					   uint16_t flags, uint16_t id,
					   uint8_t version)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;

	nlh = mnl_nlmsg_put_header(nlg->buf);
	nlh->nlmsg_type	= id;
	nlh->nlmsg_flags = flags;
	nlg->seq = time(NULL);
	nlh->nlmsg_seq = nlg->seq;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = cmd;
	genl->version = version;

	return nlh;
}

struct nlmsghdr *mnlg_msg_prepare(struct mnlg_socket *nlg, uint8_t cmd,
				  uint16_t flags)
{
	return __mnlg_msg_prepare(nlg, cmd, flags, nlg->id, nlg->version);
}

int mnlg_socket_send(struct mnlg_socket *nlg, const struct nlmsghdr *nlh)
{
	return mnl_socket_sendto(nlg->nl, nlh, nlh->nlmsg_len);
}

static int mnlg_cb_noop(const struct nlmsghdr *nlh, void *data)
{
	(void)nlh;
	(void)data;
	return MNL_CB_OK;
}

static int mnlg_cb_error(const struct nlmsghdr *nlh, void *data)
{
	const struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
	(void)data;

	if (nlh->nlmsg_len < mnl_nlmsg_size(sizeof(struct nlmsgerr))) {
		errno = EBADMSG;
		return MNL_CB_ERROR;
	}
	/* Netlink subsystems returns the errno value with different signess */
	if (err->error < 0)
		errno = -err->error;
	else
		errno = err->error;

	return err->error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
}

static int mnlg_cb_stop(const struct nlmsghdr *nlh, void *data)
{
	(void)data;
	if (nlh->nlmsg_flags & NLM_F_MULTI && nlh->nlmsg_len == mnl_nlmsg_size(sizeof(int))) {
		int error = *(int *)mnl_nlmsg_get_payload(nlh);
		/* Netlink subsystems returns the errno value with different signess */
		if (error < 0)
			errno = -error;
		else
			errno = error;

		return error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
	}
	return MNL_CB_STOP;
}

static mnl_cb_t mnlg_cb_array[] = {
	[NLMSG_NOOP]	= mnlg_cb_noop,
	[NLMSG_ERROR]	= mnlg_cb_error,
	[NLMSG_DONE]	= mnlg_cb_stop,
	[NLMSG_OVERRUN]	= mnlg_cb_noop,
};

int mnlg_socket_recv_run(struct mnlg_socket *nlg, mnl_cb_t data_cb, void *data)
{
	int err;

	do {
		err = mnl_socket_recvfrom(nlg->nl, nlg->buf,
					  MNL_SOCKET_BUFFER_SIZE);
		if (err <= 0)
			break;
		err = mnl_cb_run2(nlg->buf, err, nlg->seq, nlg->portid,
				  data_cb, data, mnlg_cb_array, MNL_ARRAY_SIZE(mnlg_cb_array));
	} while (err > 0);

	return err;
}

struct group_info {
	bool found;
	uint32_t id;
	const char *name;
};

static int parse_mc_grps_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MCAST_GRP_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case CTRL_ATTR_MCAST_GRP_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case CTRL_ATTR_MCAST_GRP_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			return MNL_CB_ERROR;
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void parse_genl_mc_grps(struct nlattr *nested,
			       struct group_info *group_info)
{
	struct nlattr *pos;
	const char *name;

	mnl_attr_for_each_nested(pos, nested) {
		struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1] = {};

		mnl_attr_parse_nested(pos, parse_mc_grps_cb, tb);
		if (!tb[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb[CTRL_ATTR_MCAST_GRP_ID])
			continue;

		name = mnl_attr_get_str(tb[CTRL_ATTR_MCAST_GRP_NAME]);
		if (strcmp(name, group_info->name) != 0)
			continue;

		group_info->id = mnl_attr_get_u32(tb[CTRL_ATTR_MCAST_GRP_ID]);
		group_info->found = true;
	}
}

static int get_group_id_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_ERROR;

	if (type == CTRL_ATTR_MCAST_GROUPS &&
	    mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0)
		return MNL_CB_ERROR;
	tb[type] = attr;
	return MNL_CB_OK;
}

static int get_group_id_cb(const struct nlmsghdr *nlh, void *data)
{
	struct group_info *group_info = data;
	struct nlattr *tb[CTRL_ATTR_MAX + 1] = { 0 };

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), get_group_id_attr_cb, tb);
	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return MNL_CB_ERROR;
	parse_genl_mc_grps(tb[CTRL_ATTR_MCAST_GROUPS], group_info);
	return MNL_CB_OK;
}

int mnlg_socket_group_add(struct mnlg_socket *nlg, const char *group_name)
{
	struct nlmsghdr *nlh;
	struct group_info group_info;
	int err;

	nlh = __mnlg_msg_prepare(nlg, CTRL_CMD_GETFAMILY,
				 NLM_F_REQUEST | NLM_F_ACK, GENL_ID_CTRL, 1);
	mnl_attr_put_u16(nlh, CTRL_ATTR_FAMILY_ID, nlg->id);

	err = mnlg_socket_send(nlg, nlh);
	if (err < 0)
		return err;

	group_info.found = false;
	group_info.name = group_name;
	err = mnlg_socket_recv_run(nlg, get_group_id_cb, &group_info);
	if (err < 0)
		return err;

	if (!group_info.found) {
		errno = ENOENT;
		return -1;
	}

	err = mnl_socket_setsockopt(nlg->nl, NETLINK_ADD_MEMBERSHIP,
				    &group_info.id, sizeof(group_info.id));
	if (err < 0)
		return err;

	return 0;
}

static int get_family_id_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_ERROR;

	if (type == CTRL_ATTR_FAMILY_ID &&
	    mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
		return MNL_CB_ERROR;
	tb[type] = attr;
	return MNL_CB_OK;
}

static int get_family_id_cb(const struct nlmsghdr *nlh, void *data)
{
	uint16_t *p_id = data;
	struct nlattr *tb[CTRL_ATTR_MAX + 1] = { 0 };

	mnl_attr_parse(nlh, sizeof(struct genlmsghdr), get_family_id_attr_cb, tb);
	if (!tb[CTRL_ATTR_FAMILY_ID])
		return MNL_CB_ERROR;
	*p_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
	return MNL_CB_OK;
}

struct mnlg_socket *mnlg_socket_open(const char *family_name, uint8_t version)
{
	struct mnlg_socket *nlg;
	struct nlmsghdr *nlh;
	int err;

	nlg = malloc(sizeof(*nlg));
	if (!nlg)
		return NULL;

	err = -ENOMEM;
	nlg->buf = malloc(MNL_SOCKET_BUFFER_SIZE);
	if (!nlg->buf)
		goto err_buf_alloc;

	nlg->nl = mnl_socket_open(NETLINK_GENERIC);
	if (!nlg->nl) {
		err = -errno;
		goto err_mnl_socket_open;
	}

	if (mnl_socket_bind(nlg->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		err = -errno;
		goto err_mnl_socket_bind;
	}

	nlg->portid = mnl_socket_get_portid(nlg->nl);

	nlh = __mnlg_msg_prepare(nlg, CTRL_CMD_GETFAMILY,
				 NLM_F_REQUEST | NLM_F_ACK, GENL_ID_CTRL, 1);
	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, family_name);

	if (mnlg_socket_send(nlg, nlh) < 0) {
		err = -errno;
		goto err_mnlg_socket_send;
	}

	errno = 0;
	if (mnlg_socket_recv_run(nlg, get_family_id_cb, &nlg->id) < 0) {
		errno = errno == ENOENT ? EPROTONOSUPPORT : errno;
		err = errno ? -errno : -ENOSYS;
		goto err_mnlg_socket_recv_run;
	}

	nlg->version = version;
	errno = 0;
	return nlg;

err_mnlg_socket_recv_run:
err_mnlg_socket_send:
err_mnl_socket_bind:
	mnl_socket_close(nlg->nl);
err_mnl_socket_open:
	free(nlg->buf);
err_buf_alloc:
	free(nlg);
	errno = -err;
	return NULL;
}

void mnlg_socket_close(struct mnlg_socket *nlg)
{
	mnl_socket_close(nlg->nl);
	free(nlg->buf);
	free(nlg);
}

#endif
