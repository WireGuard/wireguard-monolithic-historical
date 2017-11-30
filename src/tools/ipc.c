/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifdef __linux__
#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include "mnlg.h"
#endif
#include <netinet/in.h>
#include <net/if.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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
#include "containers.h"
#include "encoding.h"
#include "curve25519.h"
#include "../uapi/wireguard.h"

#define SOCK_PATH RUNSTATEDIR "/wireguard/"
#define SOCK_SUFFIX ".sock"
#ifdef __linux__
#define SOCKET_BUFFER_SIZE MNL_SOCKET_BUFFER_SIZE
#else
#define SOCKET_BUFFER_SIZE 8192
#endif


struct inflatable_buffer {
	char *buffer;
	char *next;
	bool good;
	size_t len;
	size_t pos;
};

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

static void warn_unrecognized(const char *which)
{
	static bool once = false;
	if (once)
		return;
	once = true;
	fprintf(stderr, "Warning: one or more unrecognized %s attributes\n", which);
}

static FILE *userspace_interface_file(const char *interface)
{
	struct stat sbuf;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = -1, ret;
	FILE *f = NULL;

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
	struct stat sbuf;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd, ret;

	if (strchr(interface, '/'))
		return false;
	if (snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, SOCK_PATH "%s" SOCK_SUFFIX, interface) < 0)
		return false;
	if (stat(addr.sun_path, &sbuf) < 0)
		return false;
	if (!S_ISSOCK(sbuf.st_mode))
		return false;
	ret = fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ret < 0)
		return false;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0 && errno == ECONNREFUSED) { /* If the process is gone, we try to clean up the socket. */
		close(fd);
		unlink(addr.sun_path);
		return false;
	}
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
	char hex[WG_KEY_LEN_HEX], ip[INET6_ADDRSTRLEN], host[4096 + 1], service[512 + 1];
	struct wgpeer *peer;
	struct wgallowedip *allowedip;
	FILE *f;
	int ret;
	socklen_t addr_len;

	f = userspace_interface_file(dev->name);
	if (!f)
		return -errno;
	fprintf(f, "set=1\n");

	if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY) {
		key_to_hex(hex, dev->private_key);
		fprintf(f, "private_key=%s\n", hex);
	}
	if (dev->flags & WGDEVICE_HAS_LISTEN_PORT)
		fprintf(f, "listen_port=%u\n", dev->listen_port);
	if (dev->flags & WGDEVICE_HAS_FWMARK)
		fprintf(f, "fwmark=%u\n", dev->fwmark);
	if (dev->flags & WGDEVICE_REPLACE_PEERS)
		fprintf(f, "replace_peers=true\n");

	for_each_wgpeer(dev, peer) {
		key_to_hex(hex, peer->public_key);
		fprintf(f, "public_key=%s\n", hex);
		if (peer->flags & WGPEER_REMOVE_ME) {
			fprintf(f, "remove=true\n");
			continue;
		}
		if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
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
		if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
			fprintf(f, "persistent_keepalive_interval=%u\n", peer->persistent_keepalive_interval);
		if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS)
			fprintf(f, "replace_allowed_ips=true\n");
		for_each_wgallowedip(peer, allowedip) {
			if (allowedip->family == AF_INET) {
				if (!inet_ntop(AF_INET, &allowedip->ip4, ip, INET6_ADDRSTRLEN))
					continue;
			} else if (allowedip->family == AF_INET6) {
				if (!inet_ntop(AF_INET6, &allowedip->ip6, ip, INET6_ADDRSTRLEN))
					continue;
			} else
				continue;
			fprintf(f, "allowed_ip=%s/%d\n", ip, allowedip->cidr);
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

#define NUM(max) ({ \
	unsigned long long num; \
	char *end; \
	if (!isdigit(value[0])) \
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
	struct wgallowedip *allowedip = NULL;
	size_t line_buffer_len = 0, line_len;
	char *key = NULL, *value;
	FILE *f;
	int ret = -EPROTO;

	*out = dev = calloc(1, sizeof(struct wgdevice));
	if (!dev)
		return -errno;

	f = userspace_interface_file(interface);
	if (!f)
		return -errno;

	fprintf(f, "get=1\n\n");
	fflush(f);

	strncpy(dev->name, interface, IFNAMSIZ - 1);
	dev->name[IFNAMSIZ - 1] = '\0';

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

		if (!peer && !strcmp(key, "private_key")) {
			if (!key_from_hex(dev->private_key, value))
				break;
			curve25519_generate_public(dev->public_key, dev->private_key);
			dev->flags |= WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_PUBLIC_KEY;
		} else if (!peer && !strcmp(key, "listen_port")) {
			dev->listen_port = NUM(0xffffU);
			dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
		} else if (!peer && !strcmp(key, "fwmark")) {
			dev->fwmark = NUM(0xffffffffU);
			dev->flags |= WGDEVICE_HAS_FWMARK;
		} else if (!strcmp(key, "public_key")) {
			struct wgpeer *new_peer = calloc(1, sizeof(struct wgpeer));

			if (!new_peer) {
				ret = -ENOMEM;
				goto err;
			}
			allowedip = NULL;
			if (peer)
				peer->next_peer = new_peer;
			else
				dev->first_peer = new_peer;
			peer = new_peer;
			if (!key_from_hex(peer->public_key, value))
				break;
			peer->flags |= WGPEER_HAS_PUBLIC_KEY;
		} else if (peer && !strcmp(key, "preshared_key")) {
			if (!key_from_hex(peer->preshared_key, value))
				break;
			if (!key_is_zero(peer->preshared_key))
				peer->flags |= WGPEER_HAS_PRESHARED_KEY;
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
		} else if (peer && !strcmp(key, "persistent_keepalive_interval")) {
			peer->persistent_keepalive_interval = NUM(0xffffU);
			peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
		} else if (peer && !strcmp(key, "allowed_ip")) {
			struct wgallowedip *new_allowedip;
			char *end, *mask = value, *ip = strsep(&mask, "/");

			if (!mask || !isdigit(mask[0]))
				break;
			new_allowedip = calloc(1, sizeof(struct wgallowedip));
			if (!new_allowedip) {
				ret = -ENOMEM;
				goto err;
			}
			if (allowedip)
				allowedip->next_allowedip = new_allowedip;
			else
				peer->first_allowedip = new_allowedip;
			allowedip = new_allowedip;
			allowedip->family = AF_UNSPEC;
			if (strchr(ip, ':')) {
				if (inet_pton(AF_INET6, ip, &allowedip->ip6) == 1)
					allowedip->family = AF_INET6;
			} else {
				if (inet_pton(AF_INET, ip, &allowedip->ip4) == 1)
					allowedip->family = AF_INET;
			}
			allowedip->cidr = strtoul(mask, &end, 10);
			if (*end || allowedip->family == AF_UNSPEC || (allowedip->family == AF_INET6 && allowedip->cidr > 128) || (allowedip->family == AF_INET && allowedip->cidr > 32))
				break;
		} else if (peer && !strcmp(key, "last_handshake_time_sec"))
			peer->last_handshake_time.tv_sec = NUM(0xffffffffffffffffULL);
		else if (peer && !strcmp(key, "last_handshake_time_nsec"))
			peer->last_handshake_time.tv_nsec = NUM(0xffffffffffffffffULL);
		else if (peer && !strcmp(key, "rx_bytes"))
			peer->rx_bytes = NUM(0xffffffffffffffffULL);
		else if (peer && !strcmp(key, "tx_bytes"))
			peer->tx_bytes = NUM(0xffffffffffffffffULL);
		else if (!strcmp(key, "errno"))
			ret = -NUM(0x7fffffffU);
		else
			warn_unrecognized("daemon");
	}
	ret = -EPROTO;
err:
	free(key);
	free_wgdevice(dev);
	*out = NULL;
	fclose(f);
	errno = -ret;
	return ret;

}
#undef NUM

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
	rtnl_buffer = calloc(SOCKET_BUFFER_SIZE, 1);
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
	if ((len = mnl_socket_recvfrom(nl, rtnl_buffer, SOCKET_BUFFER_SIZE)) < 0) {
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

static int kernel_set_device(struct wgdevice *dev)
{
	int ret = 0;
	size_t i, j;
	struct wgpeer *peer = NULL;
	struct wgallowedip *allowedip = NULL;
	struct nlattr *peers_nest, *peer_nest, *allowedips_nest, *allowedip_nest;
	struct nlmsghdr *nlh;
	struct mnlg_socket *nlg;

	nlg = mnlg_socket_open(WG_GENL_NAME, WG_GENL_VERSION);
	if (!nlg)
		return -errno;

again:
	nlh = mnlg_msg_prepare(nlg, WG_CMD_SET_DEVICE, NLM_F_REQUEST | NLM_F_ACK);
	mnl_attr_put_strz(nlh, WGDEVICE_A_IFNAME, dev->name);

	if (!peer) {
		uint32_t flags = 0;

		if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY)
			mnl_attr_put(nlh, WGDEVICE_A_PRIVATE_KEY, sizeof(dev->private_key), dev->private_key);
		if (dev->flags & WGDEVICE_HAS_LISTEN_PORT)
			mnl_attr_put_u16(nlh, WGDEVICE_A_LISTEN_PORT, dev->listen_port);
		if (dev->flags & WGDEVICE_HAS_FWMARK)
			mnl_attr_put_u32(nlh, WGDEVICE_A_FWMARK, dev->fwmark);
		if (dev->flags & WGDEVICE_REPLACE_PEERS)
			flags |= WGDEVICE_F_REPLACE_PEERS;
		if (flags)
			mnl_attr_put_u32(nlh, WGDEVICE_A_FLAGS, flags);
	}
	if (!dev->first_peer)
		goto send;
	peers_nest = peer_nest = allowedips_nest = allowedip_nest = NULL;
	peers_nest = mnl_attr_nest_start(nlh, WGDEVICE_A_PEERS);
	for (i = 0, peer = peer ? peer : dev->first_peer; peer; peer = peer->next_peer) {
		uint32_t flags = 0;

		peer_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, i++);
		if (!peer_nest)
			goto toobig_peers;
		if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_PUBLIC_KEY, sizeof(peer->public_key), peer->public_key))
			goto toobig_peers;
		if (peer->flags & WGPEER_REMOVE_ME)
			flags |= WGPEER_F_REMOVE_ME;
		if (!allowedip) {
			if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS)
				flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
			if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
				if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_PRESHARED_KEY, sizeof(peer->preshared_key), peer->preshared_key))
					goto toobig_peers;
			}
			if (peer->endpoint.addr.sa_family == AF_INET) {
				if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_ENDPOINT, sizeof(peer->endpoint.addr4), &peer->endpoint.addr4))
					goto toobig_peers;
			} else if (peer->endpoint.addr.sa_family == AF_INET6) {
				if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_ENDPOINT, sizeof(peer->endpoint.addr6), &peer->endpoint.addr6))
					goto toobig_peers;
			}
			if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) {
				if (!mnl_attr_put_u16_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, peer->persistent_keepalive_interval))
					goto toobig_peers;
			}
		}
		if (flags) {
			if (!mnl_attr_put_u32_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_FLAGS, flags))
				goto toobig_peers;
		}
		if (peer->first_allowedip) {
			if (!allowedip)
				allowedip = peer->first_allowedip;
			allowedips_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, WGPEER_A_ALLOWEDIPS);
			if (!allowedips_nest)
				goto toobig_allowedips;
			for (j = 0; allowedip; allowedip = allowedip->next_allowedip) {
				allowedip_nest = mnl_attr_nest_start_check(nlh, SOCKET_BUFFER_SIZE, j++);
				if (!allowedip_nest)
					goto toobig_allowedips;
				if (!mnl_attr_put_u16_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_FAMILY, allowedip->family))
					goto toobig_allowedips;
				if (allowedip->family == AF_INET) {
					if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_IPADDR, sizeof(allowedip->ip4), &allowedip->ip4))
						goto toobig_allowedips;
				} else if (allowedip->family == AF_INET6) {
					if (!mnl_attr_put_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_IPADDR, sizeof(allowedip->ip6), &allowedip->ip6))
						goto toobig_allowedips;
				}
				if (!mnl_attr_put_u8_check(nlh, SOCKET_BUFFER_SIZE, WGALLOWEDIP_A_CIDR_MASK, allowedip->cidr))
					goto toobig_allowedips;
				mnl_attr_nest_end(nlh, allowedip_nest);
				allowedip_nest = NULL;
			}
			mnl_attr_nest_end(nlh, allowedips_nest);
			allowedips_nest = NULL;
		}

		mnl_attr_nest_end(nlh, peer_nest);
		peer_nest = NULL;
	}
	mnl_attr_nest_end(nlh, peers_nest);
	peers_nest = NULL;
	goto send;
toobig_allowedips:
	if (allowedip_nest)
		mnl_attr_nest_cancel(nlh, allowedip_nest);
	if (allowedips_nest)
		mnl_attr_nest_end(nlh, allowedips_nest);
	mnl_attr_nest_end(nlh, peer_nest);
	mnl_attr_nest_end(nlh, peers_nest);
	goto send;
toobig_peers:
	if (peer_nest)
		mnl_attr_nest_cancel(nlh, peer_nest);
	mnl_attr_nest_end(nlh, peers_nest);
	goto send;
send:
	if (mnlg_socket_send(nlg, nlh) < 0) {
		ret = -errno;
		goto out;
	}
	errno = 0;
	if (mnlg_socket_recv_run(nlg, NULL, NULL) < 0) {
		ret = errno ? -errno : -EINVAL;
		goto out;
	}
	if (peer)
		goto again;

out:
	mnlg_socket_close(nlg);
	errno = -ret;
	return ret;
}

static int parse_allowedip(const struct nlattr *attr, void *data)
{
	struct wgallowedip *allowedip = data;

	switch (mnl_attr_get_type(attr)) {
	case WGALLOWEDIP_A_UNSPEC:
		break;
	case WGALLOWEDIP_A_FAMILY:
		if (!mnl_attr_validate(attr, MNL_TYPE_U16))
			allowedip->family = mnl_attr_get_u16(attr);
		break;
	case WGALLOWEDIP_A_IPADDR:
		if (mnl_attr_get_payload_len(attr) == sizeof(allowedip->ip4))
			memcpy(&allowedip->ip4, mnl_attr_get_payload(attr), sizeof(allowedip->ip4));
		else if (mnl_attr_get_payload_len(attr) == sizeof(allowedip->ip6))
			memcpy(&allowedip->ip6, mnl_attr_get_payload(attr), sizeof(allowedip->ip6));
		break;
	case WGALLOWEDIP_A_CIDR_MASK:
		if (!mnl_attr_validate(attr, MNL_TYPE_U8))
			allowedip->cidr = mnl_attr_get_u8(attr);
		break;
	default:
		warn_unrecognized("netlink");
	}

	return MNL_CB_OK;
}

static int parse_allowedips(const struct nlattr *attr, void *data)
{
	struct wgpeer *peer = data;
	struct wgallowedip *new_allowedip = calloc(1, sizeof(struct wgallowedip));
	int ret;

	if (!new_allowedip) {
		perror("calloc");
		return MNL_CB_ERROR;
	}
	if (!peer->first_allowedip)
		peer->first_allowedip = peer->last_allowedip = new_allowedip;
	else {
		peer->last_allowedip->next_allowedip = new_allowedip;
		peer->last_allowedip = new_allowedip;
	}
	ret = mnl_attr_parse_nested(attr, parse_allowedip, new_allowedip);
	if (!ret)
		return ret;
	if (!((new_allowedip->family == AF_INET && new_allowedip->cidr <= 32) || (new_allowedip->family == AF_INET6 && new_allowedip->cidr <= 128)))
		return MNL_CB_ERROR;
	return MNL_CB_OK;
}

static int parse_peer(const struct nlattr *attr, void *data)
{
	struct wgpeer *peer = data;

	switch (mnl_attr_get_type(attr)) {
	case WGPEER_A_UNSPEC:
		break;
	case WGPEER_A_PUBLIC_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(peer->public_key)) {
			memcpy(peer->public_key, mnl_attr_get_payload(attr), sizeof(peer->public_key));
			peer->flags |= WGPEER_HAS_PUBLIC_KEY;
		}
		break;
	case WGPEER_A_PRESHARED_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(peer->preshared_key)) {
			memcpy(peer->preshared_key, mnl_attr_get_payload(attr), sizeof(peer->preshared_key));
			if (!key_is_zero(peer->preshared_key))
				peer->flags |= WGPEER_HAS_PRESHARED_KEY;
		}
		break;
	case WGPEER_A_ENDPOINT: {
		struct sockaddr *addr;

		if (mnl_attr_get_payload_len(attr) < sizeof(*addr))
			break;
		addr = mnl_attr_get_payload(attr);
		if (addr->sa_family == AF_INET && mnl_attr_get_payload_len(attr) == sizeof(peer->endpoint.addr4))
			memcpy(&peer->endpoint.addr4, addr, sizeof(peer->endpoint.addr4));
		else if (addr->sa_family == AF_INET6 && mnl_attr_get_payload_len(attr) == sizeof(peer->endpoint.addr6))
			memcpy(&peer->endpoint.addr6, addr, sizeof(peer->endpoint.addr6));
		break;
	}
	case WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
		if (!mnl_attr_validate(attr, MNL_TYPE_U16))
			peer->persistent_keepalive_interval = mnl_attr_get_u16(attr);
		break;
	case WGPEER_A_LAST_HANDSHAKE_TIME:
		if (mnl_attr_get_payload_len(attr) == sizeof(peer->last_handshake_time))
			memcpy(&peer->last_handshake_time, mnl_attr_get_payload(attr), sizeof(peer->last_handshake_time));
		break;
	case WGPEER_A_RX_BYTES:
		if (!mnl_attr_validate(attr, MNL_TYPE_U64))
			peer->rx_bytes = mnl_attr_get_u64(attr);
		break;
	case WGPEER_A_TX_BYTES:
		if (!mnl_attr_validate(attr, MNL_TYPE_U64))
			peer->tx_bytes = mnl_attr_get_u64(attr);
		break;
	case WGPEER_A_ALLOWEDIPS:
		return mnl_attr_parse_nested(attr, parse_allowedips, peer);
	default:
		warn_unrecognized("netlink");
	}

	return MNL_CB_OK;
}

static int parse_peers(const struct nlattr *attr, void *data)
{
	struct wgdevice *device = data;
	struct wgpeer *new_peer = calloc(1, sizeof(struct wgpeer));
	int ret;

	if (!new_peer) {
		perror("calloc");
		return MNL_CB_ERROR;
	}
	if (!device->first_peer)
		device->first_peer = device->last_peer = new_peer;
	else {
		device->last_peer->next_peer = new_peer;
		device->last_peer = new_peer;
	}
	ret = mnl_attr_parse_nested(attr, parse_peer, new_peer);
	if (!ret)
		return ret;
	if (!(new_peer->flags & WGPEER_HAS_PUBLIC_KEY))
		return MNL_CB_ERROR;
	return MNL_CB_OK;
}

static int parse_device(const struct nlattr *attr, void *data)
{
	struct wgdevice *device = data;

	switch (mnl_attr_get_type(attr)) {
	case WGDEVICE_A_UNSPEC:
		break;
	case WGDEVICE_A_IFINDEX:
		if (!mnl_attr_validate(attr, MNL_TYPE_U32))
			device->ifindex = mnl_attr_get_u32(attr);
		break;
	case WGDEVICE_A_IFNAME:
		if (!mnl_attr_validate(attr, MNL_TYPE_STRING))
			strncpy(device->name, mnl_attr_get_str(attr), sizeof(device->name) - 1);
		break;
	case WGDEVICE_A_PRIVATE_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(device->private_key)) {
			memcpy(device->private_key, mnl_attr_get_payload(attr), sizeof(device->private_key));
			device->flags |= WGDEVICE_HAS_PRIVATE_KEY;
		}
		break;
	case WGDEVICE_A_PUBLIC_KEY:
		if (mnl_attr_get_payload_len(attr) == sizeof(device->public_key)) {
			memcpy(device->public_key, mnl_attr_get_payload(attr), sizeof(device->public_key));
			device->flags |= WGDEVICE_HAS_PUBLIC_KEY;
		}
		break;
	case WGDEVICE_A_LISTEN_PORT:
		if (!mnl_attr_validate(attr, MNL_TYPE_U16))
			device->listen_port = mnl_attr_get_u16(attr);
		break;
	case WGDEVICE_A_FWMARK:
		if (!mnl_attr_validate(attr, MNL_TYPE_U32))
			device->fwmark = mnl_attr_get_u32(attr);
		break;
	case WGDEVICE_A_PEERS:
		return mnl_attr_parse_nested(attr, parse_peers, device);
	default:
		warn_unrecognized("netlink");
	}

	return MNL_CB_OK;
}

static int read_device_cb(const struct nlmsghdr *nlh, void *data)
{
	return mnl_attr_parse(nlh, sizeof(struct genlmsghdr), parse_device, data);
}

static void coalesce_peers(struct wgdevice *device)
{
	struct wgpeer *old_next_peer, *peer = device->first_peer;

	while (peer && peer->next_peer) {
		if (memcmp(peer->public_key, peer->next_peer->public_key, WG_KEY_LEN)) {
			peer = peer->next_peer;
			continue;
		}
		if (!peer->first_allowedip) {
			peer->first_allowedip = peer->next_peer->first_allowedip;
			peer->last_allowedip = peer->next_peer->last_allowedip;
		} else {
			peer->last_allowedip->next_allowedip = peer->next_peer->first_allowedip;
			peer->last_allowedip = peer->next_peer->last_allowedip;
		}
		old_next_peer = peer->next_peer;
		peer->next_peer = old_next_peer->next_peer;
		free(old_next_peer);
	}
}

static int kernel_get_device(struct wgdevice **device, const char *interface)
{
	int ret = 0;
	struct nlmsghdr *nlh;
	struct mnlg_socket *nlg;

try_again:
	*device = calloc(1, sizeof(struct wgdevice));
	if (!*device)
		return -errno;

	nlg = mnlg_socket_open(WG_GENL_NAME, WG_GENL_VERSION);
	if (!nlg) {
		free_wgdevice(*device);
		*device = NULL;
		return -errno;
	}

	nlh = mnlg_msg_prepare(nlg, WG_CMD_GET_DEVICE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);
	mnl_attr_put_strz(nlh, WGDEVICE_A_IFNAME, interface);
	if (mnlg_socket_send(nlg, nlh) < 0) {
		ret = -errno;
		goto out;
	}
	errno = 0;
	if (mnlg_socket_recv_run(nlg, read_device_cb, *device) < 0) {
		ret = errno ? -errno : -EINVAL;
		goto out;
	}
	coalesce_peers(*device);

out:
	if (nlg)
		mnlg_socket_close(nlg);
	if (ret) {
		free_wgdevice(*device);
		if (ret == -EINTR)
			goto try_again;
		*device = NULL;
	}
	errno = -ret;
	return ret;
}
#endif

/* first\0second\0third\0forth\0last\0\0 */
char *ipc_list_devices(void)
{
	struct inflatable_buffer buffer = { .len = SOCKET_BUFFER_SIZE };
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
	if (userspace_has_wireguard_interface(dev->name))
		return userspace_set_device(dev);
	return kernel_set_device(dev);
#else
	return userspace_set_device(dev);
#endif
}
