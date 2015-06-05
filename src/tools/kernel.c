/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>

#include "kernel.h"
#include "../uapi.h"

struct inflatable_buffer {
	char *buffer;
	char *next;
	bool good;
	size_t len;
	size_t pos;
};

#define max(a, b) (a > b ? a : b)

static int add_next_to_inflatable_buffer(struct inflatable_buffer *buffer)
{
	size_t len, expand_to;
	char *new_buffer;

	if (!buffer->good || !buffer->next) {
		free(buffer->next);
		return 0;
	}

	len = strlen(buffer->next) + 1;

	if (len == 1)
		return 0;

	if (buffer->len - buffer->pos <= len) {
		expand_to = max(buffer->len * 2, buffer->len + len + 1);
		new_buffer = realloc(buffer->buffer, expand_to);
		if (!new_buffer) {
			free(buffer->next);
			return -errno;
		}
		memset(&new_buffer[buffer->len], 0, expand_to - buffer->len);
		buffer->buffer = new_buffer;
		buffer->len = expand_to;
	}
	memcpy(&buffer->buffer[buffer->pos], buffer->next, len);
	free(buffer->next);
	buffer->pos += len;
	return 0;
}

static int parse_linkinfo(const struct nlattr *attr, void *data)
{
	struct inflatable_buffer *buffer = data;
	if (mnl_attr_get_type(attr) == IFLA_INFO_KIND && !strcmp("wireguard", mnl_attr_get_str(attr)))
		buffer->good = true;
	return MNL_CB_OK;
}

static int parse_infomsg(const struct nlattr *attr, void *data)
{
	struct inflatable_buffer *buffer = data;
	if (mnl_attr_get_type(attr) == IFLA_LINKINFO)
		return mnl_attr_parse_nested(attr, parse_linkinfo, data);
	else if (mnl_attr_get_type(attr) == IFLA_IFNAME)
		buffer->next = strdup(mnl_attr_get_str(attr));
	return MNL_CB_OK;
}

static int read_devices_cb(const struct nlmsghdr *nlh, void *data)
{
	struct inflatable_buffer *buffer = data;
	buffer->good = false;
	buffer->next = NULL;
	int ret = mnl_attr_parse(nlh, sizeof(struct ifinfomsg), parse_infomsg, data);
	if (ret != MNL_CB_OK)
		return ret;
	ret = add_next_to_inflatable_buffer(buffer);
	if (ret < 0)
		return ret;
	if (nlh->nlmsg_type != NLMSG_DONE)
		return MNL_CB_OK + 1;
	return MNL_CB_OK;
}

/* first\0second\0third\0forth\0last\0\0 */
char *kernel_get_wireguard_interfaces(void)
{
	struct mnl_socket *nl = NULL;
	char *rtnl_buffer = NULL;
	size_t message_len;
	unsigned int portid, seq;
	ssize_t len;
	int ret = 0;
	struct inflatable_buffer buffer = { 0 };
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;

	buffer.len = 4096;
	buffer.buffer = calloc(buffer.len, 1);
	if (!buffer.buffer) {
		ret = -errno;
		goto cleanup;
	}

	rtnl_buffer = calloc(4096, 1);
	if (!rtnl_buffer) {
		ret = -errno;
		goto cleanup;
	}

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl) {
		ret = -errno;
		goto cleanup;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		ret = -errno;
		goto cleanup;
	}

	seq = time(NULL);
	portid = mnl_socket_get_portid(nl);
	nlh = mnl_nlmsg_put_header(rtnl_buffer);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	message_len = nlh->nlmsg_len;

	if (mnl_socket_sendto(nl, rtnl_buffer, message_len) < 0) {
		ret = -errno;
		goto cleanup;
	}

another:
	if ((len = mnl_socket_recvfrom(nl, rtnl_buffer, 4096)) < 0) {
		ret = -errno;
		goto cleanup;
	}
	if ((len = mnl_cb_run(rtnl_buffer, len, seq, portid, read_devices_cb, &buffer)) < 0) {
		ret = -errno;
		goto cleanup;
	}
	if (len == MNL_CB_OK + 1)
		goto another;

cleanup:
	free(rtnl_buffer);
	if (nl)
		mnl_socket_close(nl);
	errno = -ret;
	if (errno) {
		perror("Error when trying to get a list of Wireguard interfaces");
		free(buffer.buffer);
		return NULL;
	}
	return buffer.buffer;
}

bool kernel_has_wireguard_interface(const char *interface)
{
	char *interfaces, *this_interface;
	this_interface = interfaces = kernel_get_wireguard_interfaces();
	if (!interfaces)
		return false;
	for (size_t len = 0; (len = strlen(this_interface)); this_interface += len + 1) {
		if (!strcmp(interface, this_interface)) {
			free(interfaces);
			return true;
		}
	}
	free(interfaces);
	return false;
}

static int do_ioctl(int req, struct ifreq *ifreq)
{
	static int fd = -1;
	if (fd < 0) {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0)
			return fd;
	}
	return ioctl(fd, req, ifreq);
}

int kernel_set_device(struct wgdevice *dev)
{
	struct ifreq ifreq = { .ifr_data = (char *)dev };
	memcpy(&ifreq.ifr_name, dev->interface, IFNAMSIZ);
	ifreq.ifr_name[IFNAMSIZ - 1] = 0;
	return do_ioctl(WG_SET_DEVICE, &ifreq);
}

int kernel_get_device(struct wgdevice **dev, const char *interface)
{
	int ret;
	struct ifreq ifreq = { 0 };
	memcpy(&ifreq.ifr_name, interface, IFNAMSIZ);
	ifreq.ifr_name[IFNAMSIZ - 1] = 0;
	*dev = NULL;
	do {
		free(*dev);
		ret = do_ioctl(WG_GET_DEVICE, &ifreq);
		if (ret < 0)
			goto out;
		*dev = calloc(ret + sizeof(struct wgdevice), 1);
		if (!*dev) {
			perror("calloc");
			ret = -ENOMEM;
			goto out;
		}
		(*dev)->peers_size = ret;
		ifreq.ifr_data = (char *)*dev;
		memcpy(&ifreq.ifr_name, interface, IFNAMSIZ);
		ifreq.ifr_name[IFNAMSIZ - 1] = 0;
		ret = do_ioctl(WG_GET_DEVICE, &ifreq);
	} while (ret == -EMSGSIZE);
	if (ret < 0) {
		free(*dev);
		*dev = NULL;
	}
out:
	errno = -ret;
	return ret;
}
