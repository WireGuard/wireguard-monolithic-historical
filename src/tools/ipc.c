/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

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
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <netdb.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "ipc.h"
#include "encoding.h"
#include "curve25519.h"
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

static FILE *userspace_interface_file(const char *interface)
{
	struct stat sbuf;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = -1, ret;
	FILE *f;

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
	f = fdopen(fd, "r+");
	if (!f)
		ret = -errno;
out:
	if (ret && fd >= 0)
		close(fd);
	if (ret) {
		errno = -ret;
		return NULL;
	}
	return f;
}

static bool userspace_has_wireguard_interface(const char *interface)
{
	FILE *f = userspace_interface_file(interface);
	if (!f)
		return false;
	fclose(f);
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
	static const uint8_t zero[WG_KEY_LEN] = { 0 };
	char hex[WG_KEY_LEN_HEX], ip[INET6_ADDRSTRLEN], host[4096 + 1], service[512 + 1];
	struct wgpeer *peer;
	struct wgipmask *ipmask;
	FILE *f;
	int ret;
	size_t i, j;
	socklen_t addr_len;

	f = userspace_interface_file(dev->interface);
	if (!f)
		return -errno;
	fprintf(f, "set=1\n");

	if (dev->flags & WGDEVICE_REMOVE_PRIVATE_KEY)
		fprintf(f, "private_key=\n");
	else if (memcmp(dev->private_key, zero, WG_KEY_LEN)) {
		key_to_hex(hex, dev->private_key);
		fprintf(f, "private_key=%s\n", hex);
	}
	if (dev->port)
		fprintf(f, "listen_port=%u\n", dev->port);
	if (dev->flags & WGDEVICE_REMOVE_FWMARK)
		fprintf(f, "fwmark=\n");
	else if (dev->fwmark)
		fprintf(f, "fwmark=%u\n", dev->fwmark);
	if (dev->flags & WGDEVICE_REPLACE_PEERS)
		fprintf(f, "replace_peers=true\n");

	for_each_wgpeer(dev, peer, i) {
		key_to_hex(hex, peer->public_key);
		fprintf(f, "public_key=%s\n", hex);
		if (peer->flags & WGPEER_REMOVE_ME) {
			fprintf(f, "remove=true\n");
			continue;
		}
		if (peer->flags & WGPEER_REMOVE_PRESHARED_KEY)
			fprintf(f, "preshared_key=\n");
		else if (memcmp(peer->preshared_key, zero, WG_KEY_LEN)) {
			key_to_hex(hex, peer->preshared_key);
			fprintf(f, "preshared_key=%s\n", hex);
		}
		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6) {
			addr_len = 0;
			if (peer->endpoint.addr.sa_family == AF_INET)
				addr_len = sizeof(struct sockaddr_in);
			else if (peer->endpoint.addr.sa_family == AF_INET6)
				addr_len = sizeof(struct sockaddr_in6);
			if (!getnameinfo(&peer->endpoint.addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST)) {
				if (peer->endpoint.addr.sa_family == AF_INET6 && strchr(host, ':'))
					fprintf(f, "endpoint=[%s]:%s\n", host, service);
				else
					fprintf(f, "endpoint=%s:%s\n", host, service);
			}
		}
		if (peer->persistent_keepalive_interval != (uint16_t)-1)
			fprintf(f, "persistent_keepalive_interval=%u\n", peer->persistent_keepalive_interval);
		if (peer->flags & WGPEER_REPLACE_IPMASKS)
			fprintf(f, "replace_allowed_ips=true\n");
		for_each_wgipmask(peer, ipmask, j) {
			if (ipmask->family == AF_INET) {
				if (!inet_ntop(AF_INET, &ipmask->ip4, ip, INET6_ADDRSTRLEN))
					continue;
			} else if (ipmask->family == AF_INET6) {
				if (!inet_ntop(AF_INET6, &ipmask->ip6, ip, INET6_ADDRSTRLEN))
					continue;
			} else
				continue;
			fprintf(f, "allowed_ip=%s/%d\n", ip, ipmask->cidr);
		}
	}
	fprintf(f, "\n");
	fflush(f);

	if (fscanf(f, "errno=%d\n\n", &ret) != 1)
		ret = errno ? -errno : -EPROTO;
	fclose(f);
	errno = -ret;
	return ret;
}

#define ADD(bytes) ({ \
	if (buffer_len - buffer_end < bytes) { \
		ptrdiff_t peer_offset = (void *)peer - (void *)*out; \
		buffer_len = buffer_len * 2 + bytes; \
		*out = realloc(*out, buffer_len); \
		if (!*out) { \
			ret = -errno; \
			goto err; \
		} \
		memset((void *)*out + buffer_end, 0, buffer_len - buffer_end); \
		if (peer) \
			peer = (void *)*out + peer_offset; \
		dev = *out; \
	} \
	buffer_end += bytes; \
	(void *)*out + buffer_end - bytes; \
})

#define NUM(max) ({ \
	unsigned long long num; \
	char *end; \
	if (!strlen(value)) \
		break; \
	num = strtoull(value, &end, 10); \
	if (*end || num > max) \
		break; \
	num; \
})

static int userspace_get_device(struct wgdevice **out, const char *interface)
{
	struct wgdevice *dev;
	struct wgpeer *peer = NULL;
	size_t buffer_len = 0, buffer_end = 0, line_buffer_len = 0, line_len;
	char *key = NULL, *value;
	FILE *f;
	int ret = -EPROTO;

	f = userspace_interface_file(interface);
	if (!f)
		return -errno;

	fprintf(f, "get=1\n\n");
	fflush(f);

	*out = NULL;
	dev = ADD(sizeof(struct wgdevice));
	dev->version_magic = WG_API_VERSION_MAGIC;
	strncpy(dev->interface, interface, IFNAMSIZ - 1);
	dev->interface[IFNAMSIZ - 1] = '\0';

	while (getline(&key, &line_buffer_len, f) > 0) {
		line_len = strlen(key);
		if (line_len == 1 && key[0] == '\n') {
			free(key);
			fclose(f);
			return ret;
		}
		value = strchr(key, '=');
		if (!value || line_len == 0 || key[line_len - 1] != '\n')
			break;
		*value++ = key[--line_len] = '\0';

		if (!strcmp(key, "private_key")) {
			if (!key_from_hex(dev->private_key, value))
				break;
			curve25519_generate_public(dev->public_key, dev->private_key);
		} else if (!strcmp(key, "listen_port"))
			dev->port = NUM(0xffffU);
		else if (!strcmp(key, "fwmark"))
			dev->fwmark = NUM(0xffffffffU);
		else if (!strcmp(key, "public_key")) {
			peer = ADD(sizeof(struct wgpeer));
			if (!key_from_hex(peer->public_key, value))
				break;
			++dev->num_peers;
		} else if (peer && !strcmp(key, "preshared_key")) {
			if (!key_from_hex(peer->preshared_key, value))
				break;
		} else if (peer && !strcmp(key, "endpoint")) {
			char *begin, *end;
			struct addrinfo *resolved;
			struct addrinfo hints = {
				.ai_family = AF_UNSPEC,
				.ai_socktype = SOCK_DGRAM,
				.ai_protocol = IPPROTO_UDP
			};
			if (!strlen(value))
				break;
			if (value[0] == '[') {
				begin = &value[1];
				end = strchr(value, ']');
				if (!end)
					break;
				*end++ = '\0';
				if (*end++ != ':' || !*end)
					break;
			} else {
				begin = value;
				end = strrchr(value, ':');
				if (!end || !*(end + 1))
					break;
				*end++ = '\0';
			}
			if (getaddrinfo(begin, end, &hints, &resolved) != 0) {
				errno = ENETUNREACH;
				goto err;
			}
			if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) ||
			    (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)))
				memcpy(&peer->endpoint.addr, resolved->ai_addr, resolved->ai_addrlen);
			else  {
				freeaddrinfo(resolved);
				break;
			}
			freeaddrinfo(resolved);
		} else if (peer && !strcmp(key, "persistent_keepalive_interval"))
			peer->persistent_keepalive_interval = NUM(65535U);
		else if (peer && !strcmp(key, "allowed_ip")) {
			struct wgipmask *ipmask = ADD(sizeof(struct wgipmask));
			char *end, *cidr = strchr(value, '/');
			if (!cidr || strlen(cidr) <= 1)
				break;
			*cidr++ = '\0';
			ipmask->family = AF_UNSPEC;
			if (strchr(value, ':')) {
				if (inet_pton(AF_INET6, value, &ipmask->ip6) == 1)
					ipmask->family = AF_INET6;
			} else {
				if (inet_pton(AF_INET, value, &ipmask->ip4) == 1)
					ipmask->family = AF_INET;
			}
			ipmask->cidr = strtoul(cidr, &end, 10);
			if (*end || ipmask->family == AF_UNSPEC || (ipmask->family == AF_INET6 && ipmask->cidr > 128) || (ipmask->family == AF_INET && ipmask->cidr > 32))
				break;
			++peer->num_ipmasks;
		} else if (peer && !strcmp(key, "last_handshake_time_sec"))
			peer->last_handshake_time.tv_sec = NUM(0xffffffffffffffffULL);
		else if (peer && !strcmp(key, "last_handshake_time_nsec"))
			peer->last_handshake_time.tv_usec = NUM(0xffffffffffffffffULL) / 1000;
		else if (peer && !strcmp(key, "rx_bytes"))
			peer->rx_bytes = NUM(0xffffffffffffffffULL);
		else if (peer && !strcmp(key, "tx_bytes"))
			peer->tx_bytes = NUM(0xffffffffffffffffULL);
		else if (!strcmp(key, "errno"))
			ret = -NUM(0x7fffffffU);
		else
			break;
	}
	ret = -EPROTO;
err:
	free(key);
	free(*out);
	*out = NULL;
	fclose(f);
	errno = -ret;
	return ret;

}
#undef ADD
#undef NUM
#undef KEY

#ifdef __linux__
static int check_version_magic(struct wgdevice *device, int ret)
{
	if (ret == -EPROTO || (!ret && device->version_magic != WG_API_VERSION_MAGIC)) {
		fprintf(stderr, "This program was built for a different version of WireGuard than\nwhat is currently running. Either this version of wg(8) is out\nof date, or the currently loaded WireGuard module is out of date.\nIf you have just updated your WireGuard installation, you may have\nforgotten to unload the previous running WireGuard module. Try\nrunning `rmmod wireguard` as root, and then try re-adding the interface\nand trying again.\n\n");
		errno = EPROTO;
		return -EPROTO;
	}
	return ret;
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
	int ret;

	buffer->good = false;
	buffer->next = NULL;
	ret = mnl_attr_parse(nlh, sizeof(struct ifinfomsg), parse_infomsg, data);
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

	buffer.buffer = calloc(1, buffer.len);
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
	int ret;
	if (fd < 0) {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0)
			return fd;
	}
	ret = ioctl(fd, req, ifreq);
	if (ret == -1)
		ret = -errno;
	return ret;
}

static int kernel_set_device(struct wgdevice *dev)
{
	struct ifreq ifreq = { .ifr_data = (char *)dev };
	memcpy(&ifreq.ifr_name, dev->interface, IFNAMSIZ);
	ifreq.ifr_name[IFNAMSIZ - 1] = 0;
	dev->version_magic = WG_API_VERSION_MAGIC;
	return check_version_magic(dev, do_ioctl(WG_SET_DEVICE, &ifreq));
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
		*dev = calloc(1, ret + sizeof(struct wgdevice));
		ret = -ENOMEM;
		if (!*dev)
			goto out;
		(*dev)->peers_size = ret;
		(*dev)->version_magic = WG_API_VERSION_MAGIC;
		ifreq.ifr_data = (char *)*dev;
		memcpy(&ifreq.ifr_name, interface, IFNAMSIZ);
		ifreq.ifr_name[IFNAMSIZ - 1] = 0;
		ret = do_ioctl(WG_GET_DEVICE, &ifreq);
	} while (ret == -EMSGSIZE);
	ret = check_version_magic(*dev, ret);
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
	buffer.buffer = calloc(1, buffer.len);
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
