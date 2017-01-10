/* Copyright (C) 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifdef __linux__
#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "ipc.h"
#include "../uapi.h"

#define SOCK_PATH RUNSTATEDIR "/wireguard/"
#define SOCK_SUFFIX ".sock"

struct inflatable_buffer {
	char *buffer;
	char *next;
	bool good;
	size_t len;
	size_t pos;
};

#define max(a, b) ((a) > (b) ? (a) : (b))

static int add_next_to_inflatable_buffer(struct inflatable_buffer *buffer)
{
	size_t len, expand_to;
	char *new_buffer;

	if (!buffer->good || !buffer->next) {
		free(buffer->next);
		buffer->good = false;
		return 0;
	}

	len = strlen(buffer->next) + 1;

	if (len == 1) {
		free(buffer->next);
		buffer->good = false;
		return 0;
	}

	if (buffer->len - buffer->pos <= len) {
		expand_to = max(buffer->len * 2, buffer->len + len + 1);
		new_buffer = realloc(buffer->buffer, expand_to);
		if (!new_buffer) {
			free(buffer->next);
			buffer->good = false;
			return -errno;
		}
		memset(&new_buffer[buffer->len], 0, expand_to - buffer->len);
		buffer->buffer = new_buffer;
		buffer->len = expand_to;
	}
	memcpy(&buffer->buffer[buffer->pos], buffer->next, len);
	free(buffer->next);
	buffer->good = false;
	buffer->pos += len;
	return 0;
}

static int userspace_interface_fd(const char *interface)
{
	struct stat sbuf;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = -1, ret;

	ret = -EINVAL;
	if (strchr(interface, '/'))
		goto out;
	ret = snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, SOCK_PATH "%s" SOCK_SUFFIX, interface);
	if (ret < 0)
		goto out;
	ret = stat(addr.sun_path, &sbuf);
	if (ret < 0)
		goto out;
	ret = -EBADF;
	if (!S_ISSOCK(sbuf.st_mode))
		goto out;

	ret = fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ret < 0)
		goto out;

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		if (errno == ECONNREFUSED) /* If the process is gone, we try to clean up the socket. */
			unlink(addr.sun_path);
		goto out;
	}
out:
	if (ret && fd >= 0)
		close(fd);
	if (!ret)
		ret = fd;
	return ret;
}

static bool userspace_has_wireguard_interface(const char *interface)
{
	int fd = userspace_interface_fd(interface);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static int userspace_get_wireguard_interfaces(struct inflatable_buffer *buffer)
{
	DIR *dir;
	struct dirent *ent;
	size_t len;
	char *end;
	int ret = 0;

	dir = opendir(SOCK_PATH);
	if (!dir)
		return errno == ENOENT ? 0 : errno;
	while ((ent = readdir(dir))) {
		len = strlen(ent->d_name);
		if (len <= strlen(SOCK_SUFFIX))
			continue;
		end = &ent->d_name[len - strlen(SOCK_SUFFIX)];
		if (strncmp(end, SOCK_SUFFIX, strlen(SOCK_SUFFIX)))
			continue;
		*end = '\0';
		if (!userspace_has_wireguard_interface(ent->d_name))
			continue;
		buffer->next = strdup(ent->d_name);
		buffer->good = true;
		ret = add_next_to_inflatable_buffer(buffer);
		if (ret < 0)
			goto out;
	}
out:
	closedir(dir);
	return ret;
}

static int userspace_set_device(struct wgdevice *dev)
{
	struct wgpeer *peer;
	size_t len;
	ssize_t ret;
	int ret_code;
	int fd = userspace_interface_fd(dev->interface);
	if (fd < 0)
		return fd;
	for_each_wgpeer(dev, peer, len);
	len = (unsigned char *)peer - (unsigned char *)dev;
	ret = -EBADMSG;
	if (!len)
		goto out;
	ret = write(fd, dev, len);
	if (ret < 0)
		goto out;
	ret = read(fd, &ret_code, sizeof(ret_code));
	if (ret < 0)
		goto out;
	if (ret != sizeof(ret_code)) {
		ret = -EBADMSG;
		goto out;
	}
	ret = ret_code;
out:
	close(fd);
	errno = -ret;
	return (int)ret;
}

#define READ_BYTES(bytes) ({ \
	void *__p; \
	size_t __bytes = (bytes); \
	if (bytes_left < __bytes) { \
		offset = p - buffer; \
		bytes_left += buffer_size; \
		buffer_size *= 2; \
		ret = -ENOMEM; \
		p = realloc(buffer, buffer_size); \
		if (!p) \
			goto out; \
		buffer = p; \
		p += offset; \
	} \
	bytes_left -= __bytes; \
	ret = read(fd, p, __bytes); \
	if (ret < 0) \
		goto out; \
	if ((size_t)ret != __bytes) { \
		ret = -EBADMSG; \
		goto out; \
	} \
	__p = p; \
	p += __bytes; \
	__p; \
})
static int userspace_get_device(struct wgdevice **dev, const char *interface)
{
	unsigned int len = 0, i;
	size_t buffer_size, bytes_left;
	ssize_t ret;
	ptrdiff_t offset;
	uint8_t *buffer = NULL, *p, byte = 0;

	int fd = userspace_interface_fd(interface);
	if (fd < 0)
		return fd;

	ret = write(fd, &byte, sizeof(byte));
	if (ret < 0)
		goto out;
	if (ret != sizeof(byte)) {
		ret = -EBADMSG;
		goto out;
	}

	ioctl(fd, FIONREAD, &len);
	bytes_left = buffer_size = max(len, sizeof(struct wgdevice) + sizeof(struct wgpeer) + sizeof(struct wgipmask));
	p = buffer = malloc(buffer_size);
	ret = -ENOMEM;
	if (!buffer)
		goto out;

	len = ((struct wgdevice *)READ_BYTES(sizeof(struct wgdevice)))->num_peers;
	for (i = 0; i < len; ++i)
		READ_BYTES(sizeof(struct wgipmask) * ((struct wgpeer *)READ_BYTES(sizeof(struct wgpeer)))->num_ipmasks);
	ret = 0;
out:
	if (buffer && ret) {
		free(buffer);
		buffer = NULL;
	}
	*dev = (struct wgdevice *)buffer;
	close(fd);
	errno = -ret;
	return ret;

}
#undef READ_BYTES

#ifdef __linux__
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

static int kernel_get_wireguard_interfaces(struct inflatable_buffer *buffer)
{
	struct mnl_socket *nl = NULL;
	char *rtnl_buffer = NULL;
	size_t message_len;
	unsigned int portid, seq;
	ssize_t len;
	int ret = 0;
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;

	ret = -ENOMEM;
	rtnl_buffer = calloc(4096, 1);
	if (!rtnl_buffer)
		goto cleanup;

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
	if ((len = mnl_cb_run(rtnl_buffer, len, seq, portid, read_devices_cb, buffer)) < 0) {
		ret = -errno;
		goto cleanup;
	}
	if (len == MNL_CB_OK + 1)
		goto another;
	ret = 0;

cleanup:
	free(rtnl_buffer);
	if (nl)
		mnl_socket_close(nl);
	return ret;
}

static bool kernel_has_wireguard_interface(const char *interface)
{
	char *this_interface;
	struct inflatable_buffer buffer = { .len = 4096 };

	buffer.buffer = calloc(buffer.len, 1);
	if (!buffer.buffer)
		return false;
	if (kernel_get_wireguard_interfaces(&buffer) < 0) {
		free(buffer.buffer);
		return false;
	}
	this_interface = buffer.buffer;
	for (size_t len = 0; (len = strlen(this_interface)); this_interface += len + 1) {
		if (!strcmp(interface, this_interface)) {
			free(buffer.buffer);
			return true;
		}
	}
	free(buffer.buffer);
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

static int kernel_set_device(struct wgdevice *dev)
{
	struct ifreq ifreq = { .ifr_data = (char *)dev };
	memcpy(&ifreq.ifr_name, dev->interface, IFNAMSIZ);
	ifreq.ifr_name[IFNAMSIZ - 1] = 0;
	return do_ioctl(WG_SET_DEVICE, &ifreq);
}

static int kernel_get_device(struct wgdevice **dev, const char *interface)
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
#endif

/* first\0second\0third\0forth\0last\0\0 */
char *ipc_list_devices(void)
{
	struct inflatable_buffer buffer = { .len = 4096 };
	int ret;

	ret = -ENOMEM;
	buffer.buffer = calloc(buffer.len, 1);
	if (!buffer.buffer)
		goto cleanup;

#ifdef __linux__
	ret = kernel_get_wireguard_interfaces(&buffer);
	if (ret < 0)
		goto cleanup;
#endif
	ret = userspace_get_wireguard_interfaces(&buffer);
	if (ret < 0)
		goto cleanup;

cleanup:
	errno = -ret;
	if (errno) {
		perror("Error when trying to get a list of WireGuard interfaces");
		free(buffer.buffer);
		return NULL;
	}
	return buffer.buffer;
}

int ipc_get_device(struct wgdevice **dev, const char *interface)
{
#ifdef __linux__
	if (userspace_has_wireguard_interface(interface))
		return userspace_get_device(dev, interface);
	return kernel_get_device(dev, interface);
#else
	return userspace_get_device(dev, interface);
#endif
}

int ipc_set_device(struct wgdevice *dev)
{
#ifdef __linux__
	if (userspace_has_wireguard_interface(dev->interface))
		return userspace_set_device(dev);
	return kernel_set_device(dev);
#else
	return userspace_set_device(dev);
#endif
}

bool ipc_has_device(const char *interface)
{
#ifdef __linux__
	return userspace_has_wireguard_interface(interface) || kernel_has_wireguard_interface(interface);
#else
	return userspace_has_wireguard_interface(interface);
#endif
}
