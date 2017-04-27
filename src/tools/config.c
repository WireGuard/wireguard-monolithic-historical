/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */


#include <arpa/inet.h>
#include <limits.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>

#include "config.h"
#include "ipc.h"
#include "base64.h"

#define COMMENT_CHAR '#'

#define max(a, b) (a > b ? a : b)

static inline struct wgpeer *peer_from_offset(struct wgdevice *dev, size_t offset)
{
	return (struct wgpeer *)((uint8_t *)dev + sizeof(struct wgdevice) + offset);
}

static int use_space(struct inflatable_device *buf, size_t space)
{
	size_t expand_to;
	uint8_t *new_dev;

	if (buf->len - buf->pos < space) {
		expand_to = max(buf->len * 2, buf->len + space);
		new_dev = realloc(buf->dev, expand_to + sizeof(struct wgdevice));
		if (!new_dev)
			return -errno;
		memset(&new_dev[buf->len + sizeof(struct wgdevice)], 0, expand_to - buf->len);
		buf->dev = (struct wgdevice *)new_dev;
		buf->len = expand_to;
	}
	buf->pos += space;
	return 0;
}

static const char *get_value(const char *line, const char *key)
{
	size_t linelen = strlen(line);
	size_t keylen = strlen(key);

	if (keylen >= linelen)
		return NULL;

	if (strncasecmp(line, key, keylen))
		return NULL;

	return line + keylen;
}

static inline uint16_t parse_port(const char *value)
{
	int ret;
	uint16_t port = 0;
	struct addrinfo *resolved;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = AI_PASSIVE
	};

	if (!strlen(value)) {
		fprintf(stderr, "Unable to parse empty port\n");
		return 0;
	}

	ret = getaddrinfo(NULL, value, &hints, &resolved);
	if (ret != 0) {
		fprintf(stderr, "%s: `%s`\n", gai_strerror(ret), value);
		return 0;
	}

	if (resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in))
		port = ntohs(((struct sockaddr_in *)resolved->ai_addr)->sin_port);
	else if (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6))
		port = ntohs(((struct sockaddr_in6 *)resolved->ai_addr)->sin6_port);
	else
		fprintf(stderr, "Neither IPv4 nor IPv6 address found: `%s`\n", value);

	freeaddrinfo(resolved);
	return port;
}

static inline bool parse_fwmark(uint32_t *fwmark, unsigned int *flags, const char *value)
{
	unsigned long ret;
	char *end;
	int base = 10;

	if (!strcasecmp(value, "off")) {
		*fwmark = 0;
		*flags |= WGDEVICE_REMOVE_FWMARK;
		return true;
	}

	if (value[0] == '0' && value[1] == 'x') {
		value += 2;
		base = 16;
	}
	ret = strtoul(value, &end, base);
	if (!*value || *end || ret > UINT32_MAX)
		return false;
	*fwmark = ret;
	if (!ret)
		*flags |= WGDEVICE_REMOVE_FWMARK;
	return true;
}

static inline bool parse_key(uint8_t key[static WG_KEY_LEN], const char *value)
{
	if (!key_from_base64(key, value)) {
		fprintf(stderr, "Key is not the correct length or format: `%s`\n", value);
		return false;
	}
	return true;
}

static inline bool parse_ip(struct wgipmask *ipmask, const char *value)
{
	ipmask->family = AF_UNSPEC;
	if (strchr(value, ':')) {
		if (inet_pton(AF_INET6, value, &ipmask->ip6) == 1)
			ipmask->family = AF_INET6;
	} else {
		if (inet_pton(AF_INET, value, &ipmask->ip4) == 1)
			ipmask->family = AF_INET;
	}
	if (ipmask->family == AF_UNSPEC) {
		fprintf(stderr, "Unable to parse IP address: `%s`\n", value);
		return false;
	}
	return true;
}

static inline bool parse_endpoint(struct sockaddr *endpoint, const char *value)
{
	char *mutable = strdup(value);
	char *begin, *end;
	int ret;
	struct addrinfo *resolved;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};
	if (!mutable) {
		perror("strdup");
		return false;
	}
	if (!strlen(value)) {
		free(mutable);
		fprintf(stderr, "Unable to parse empty endpoint\n");
		return false;
	}
	if (mutable[0] == '[') {
		begin = &mutable[1];
		end = strchr(mutable, ']');
		if (!end) {
			free(mutable);
			fprintf(stderr, "Unable to find matching brace of endpoint: `%s`\n", value);
			return false;
		}
		*end = '\0';
		++end;
		if (*end != ':' || !*(end + 1)) {
			free(mutable);
			fprintf(stderr, "Unable to find port of endpoint: `%s`\n", value);
			return false;
		}
		++end;
	} else {
		begin = mutable;
		end = strrchr(mutable, ':');
		if (!end || !*(end + 1)) {
			free(mutable);
			fprintf(stderr, "Unable to find port of endpoint: `%s`\n", value);
			return false;
		}
		*end = '\0';
		++end;
	}

	for (unsigned int timeout = 1000000; timeout < 90000000; timeout = timeout * 3 / 2) {
		ret = getaddrinfo(begin, end, &hints, &resolved);
		if (ret != EAI_AGAIN)
			break;
		fprintf(stderr, "%s: `%s`. Trying again in %.2f seconds...\n", gai_strerror(ret), value, timeout / 1000000.0);
		usleep(timeout);
	}

	if (ret != 0) {
		free(mutable);
		fprintf(stderr, "%s: `%s`\n", gai_strerror(ret), value);
		return false;
	}
	if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) ||
	    (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)))
		memcpy(endpoint, resolved->ai_addr, resolved->ai_addrlen);
	else {
		freeaddrinfo(resolved);
		free(mutable);
		fprintf(stderr, "Neither IPv4 nor IPv6 address found: `%s`\n", value);
		return false;
	}
	freeaddrinfo(resolved);
	free(mutable);
	return true;
}

static inline bool parse_persistent_keepalive(__u16 *interval, const char *value)
{
	unsigned long ret;
	char *end;

	if (!strcasecmp(value, "off")) {
		*interval = 0;
		return true;
	}

	ret = strtoul(value, &end, 10);
	if (!*value || *value == '-' || *end || ret > 65535) {
		fprintf(stderr, "The persistent keepalive interval must be 0/off or 1-65535. Found: `%s`\n", value);
		return false;
	}

	*interval = (__u16)ret;
	return true;
}


static inline bool parse_ipmasks(struct inflatable_device *buf, size_t peer_offset, const char *value)
{
	struct wgpeer *peer;
	struct wgipmask *ipmask;
	char *mask, *mutable = strdup(value), *sep;
	if (!mutable) {
		perror("strdup");
		return false;
	};
	peer = peer_from_offset(buf->dev, peer_offset);
	peer->flags |= WGPEER_REPLACE_IPMASKS;
	if (!strlen(value)) {
		free(mutable);
		return true;
	}
	sep = mutable;
	while ((mask = strsep(&sep, ","))) {
		unsigned long cidr = ULONG_MAX;
		char *end, *ip = strsep(&mask, "/");
		if (use_space(buf, sizeof(struct wgipmask)) < 0) {
			perror("use_space");
			free(mutable);
			return false;
		}
		peer = peer_from_offset(buf->dev, peer_offset);
		ipmask = (struct wgipmask *)((uint8_t *)peer + sizeof(struct wgpeer) + (sizeof(struct wgipmask) * peer->num_ipmasks));

		if (!parse_ip(ipmask, ip)) {
			free(mutable);
			return false;
		}
		if (mask && *mask) {
			cidr = strtoul(mask, &end, 10);
			if (*end)
				cidr = ULONG_MAX;
		}
		if (ipmask->family == AF_INET)
			cidr = cidr > 32 ? 32 : cidr;
		else if (ipmask->family == AF_INET6)
			cidr = cidr > 128 ? 128 : cidr;
		else
			continue;
		ipmask->cidr = cidr;
		++peer->num_ipmasks;
	}
	free(mutable);
	return true;
}

static bool process_line(struct config_ctx *ctx, const char *line)
{
	const char *value;
	bool ret = true;

	if (!strcasecmp(line, "[Interface]")) {
		ctx->is_peer_section = false;
		ctx->is_device_section = true;
		return true;
	}
	if (!strcasecmp(line, "[Peer]")) {
		ctx->peer_offset = ctx->buf.pos;
		if (use_space(&ctx->buf, sizeof(struct wgpeer)) < 0) {
			perror("use_space");
			return false;
		}
		++ctx->buf.dev->num_peers;
		ctx->is_peer_section = true;
		ctx->is_device_section = false;
		peer_from_offset(ctx->buf.dev, ctx->peer_offset)->flags |= WGPEER_REPLACE_IPMASKS;
		peer_from_offset(ctx->buf.dev, ctx->peer_offset)->persistent_keepalive_interval = (__u16)-1;
		return true;
	}

#define key_match(key) (value = get_value(line, key "="))

	if (ctx->is_device_section) {
		if (key_match("ListenPort"))
			ret = !!(ctx->buf.dev->port = parse_port(value));
		else if (key_match("FwMark"))
			ret = parse_fwmark(&ctx->buf.dev->fwmark, &ctx->buf.dev->flags, value);
		else if (key_match("PrivateKey")) {
			ret = parse_key(ctx->buf.dev->private_key, value);
			if (!ret)
				memset(ctx->buf.dev->private_key, 0, WG_KEY_LEN);
		} else
			goto error;
	} else if (ctx->is_peer_section) {
		if (key_match("Endpoint"))
			ret = parse_endpoint(&peer_from_offset(ctx->buf.dev, ctx->peer_offset)->endpoint.addr, value);
		else if (key_match("PublicKey"))
			ret = parse_key(peer_from_offset(ctx->buf.dev, ctx->peer_offset)->public_key, value);
		else if (key_match("AllowedIPs"))
			ret = parse_ipmasks(&ctx->buf, ctx->peer_offset, value);
		else if (key_match("PersistentKeepalive"))
			ret = parse_persistent_keepalive(&peer_from_offset(ctx->buf.dev, ctx->peer_offset)->persistent_keepalive_interval, value);
		else if (key_match("PresharedKey")) {
			ret = parse_key(peer_from_offset(ctx->buf.dev, ctx->peer_offset)->preshared_key, value);
			if (!ret)
				memset(peer_from_offset(ctx->buf.dev, ctx->peer_offset)->preshared_key, 0, WG_KEY_LEN);
		} else
			goto error;
	} else
		goto error;
	return ret;

#undef key_match

error:
	fprintf(stderr, "Line unrecognized: `%s'\n", line);
	return false;
}

bool config_read_line(struct config_ctx *ctx, const char *input)
{
	size_t len = strlen(input), cleaned_len = 0;
	char *line = calloc(len + 1, sizeof(char));
	bool ret = true;
	if (!line) {
		perror("calloc");
		return false;
	}
	if (!len)
		goto out;
	for (size_t i = 0; i < len; ++i) {
		if (!isspace(input[i]))
			line[cleaned_len++] = input[i];
	}
	if (!cleaned_len)
		goto out;
	if (line[0] == COMMENT_CHAR)
		goto out;
	ret = process_line(ctx, line);
out:
	free(line);
	return ret;
}

bool config_read_init(struct config_ctx *ctx, struct wgdevice **device, bool append)
{
	memset(ctx, 0, sizeof(struct config_ctx));
	ctx->device = device;
	ctx->buf.dev = calloc(1, sizeof(struct wgdevice));
	if (!ctx->buf.dev) {
		perror("calloc");
		return false;
	}
	if (!append)
		ctx->buf.dev->flags |= WGDEVICE_REPLACE_PEERS;
	return true;
}

static inline bool key_is_valid(uint8_t key[WG_KEY_LEN])
{
	static const uint8_t zero[WG_KEY_LEN] = { 0 };
	return !!memcmp(key, zero, WG_KEY_LEN);
}

bool config_read_finish(struct config_ctx *ctx)
{
	size_t i;
	struct wgpeer *peer;
	if (ctx->buf.dev->flags & WGDEVICE_REPLACE_PEERS && !ctx->buf.dev->num_peers) {
		fprintf(stderr, "No peers configured\n");
		goto err;
	}
	if (ctx->buf.dev->flags & WGDEVICE_REPLACE_PEERS && !key_is_valid(ctx->buf.dev->private_key)) {
		fprintf(stderr, "No private key configured\n");
		goto err;
	}
	if (ctx->buf.dev->flags & WGDEVICE_REPLACE_PEERS && !ctx->buf.dev->fwmark)
		ctx->buf.dev->flags |= WGDEVICE_REMOVE_FWMARK;

	for_each_wgpeer(ctx->buf.dev, peer, i) {
		if (!key_is_valid(peer->public_key)) {
			fprintf(stderr, "A peer is missing a public key\n");
			goto err;
		}
	}
	*ctx->device = ctx->buf.dev;
	return true;
err:
	free(ctx->buf.dev);
	return false;
}

static int read_line(char **dst, const char *path)
{
	FILE *f;
	size_t n = 0;

	*dst = NULL;

	f = fopen(path, "r");
	if (!f) {
		perror("fopen");
		return -1;
	}
	if (getline(dst, &n, f) < 0 && errno) {
		perror("getline");
		fclose(f);
		return -1;
	}
	fclose(f);
	n = strlen(*dst);
	if (!n)
		return 1;
	while (--n) {
		if (isspace((*dst)[n]))
			(*dst)[n] = '\0';
	}
	return 0;
}

static char *strip_spaces(const char *in)
{
	char *out;
	size_t t, l, i;

	t = strlen(in);
	out = calloc(t + 1, sizeof(char));
	if (!out) {
		perror("calloc");
		return NULL;
	}
	for (i = 0, l = 0; i < t; ++i) {
		if (!isspace(in[i]))
			out[l++] = in[i];
	}
	return out;
}

bool config_read_cmd(struct wgdevice **device, char *argv[], int argc)
{
	struct inflatable_device buf = { 0 };
	size_t peer_offset = 0;
	buf.dev = calloc(1, sizeof(struct wgdevice));
	if (!buf.dev) {
		perror("calloc");
		return false;
	}
	while (argc > 0) {
		if (!strcmp(argv[0], "listen-port") && argc >= 2 && !buf.dev->num_peers) {
			buf.dev->port = parse_port(argv[1]);
			if (!buf.dev->port)
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "fwmark") && argc >= 2 && !buf.dev->num_peers) {
			if (!parse_fwmark(&buf.dev->fwmark, &buf.dev->flags, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "private-key") && argc >= 2 && !buf.dev->num_peers) {
			char *line;
			int ret = read_line(&line, argv[1]);
			if (ret == 0) {
				if (!parse_key(buf.dev->private_key, line)) {
					free(line);
					goto error;
				}
				free(line);
			} else if (ret == 1)
				buf.dev->flags |= WGDEVICE_REMOVE_PRIVATE_KEY;
			else
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "peer") && argc >= 2) {
			peer_offset = buf.pos;
			if (use_space(&buf, sizeof(struct wgpeer)) < 0) {
				perror("use_space");
				goto error;
			}
			peer_from_offset(buf.dev, peer_offset)->persistent_keepalive_interval = (__u16)-1;
			++buf.dev->num_peers;
			if (!parse_key(peer_from_offset(buf.dev, peer_offset)->public_key, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "remove") && argc >= 1 && buf.dev->num_peers) {
			peer_from_offset(buf.dev, peer_offset)->flags |= WGPEER_REMOVE_ME;
			argv += 1;
			argc -= 1;
		} else if (!strcmp(argv[0], "endpoint") && argc >= 2 && buf.dev->num_peers) {
			if (!parse_endpoint(&peer_from_offset(buf.dev, peer_offset)->endpoint.addr, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "allowed-ips") && argc >= 2 && buf.dev->num_peers) {
			char *line = strip_spaces(argv[1]);
			if (!line)
				goto error;
			if (!parse_ipmasks(&buf, peer_offset, line)) {
				free(line);
				goto error;
			}
			free(line);
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "persistent-keepalive") && argc >= 2 && buf.dev->num_peers) {
			if (!parse_persistent_keepalive(&peer_from_offset(buf.dev, peer_offset)->persistent_keepalive_interval, argv[1]))
				goto error;
			argv += 2;
			argc -= 2;
		} else if (!strcmp(argv[0], "preshared-key") && argc >= 2 && buf.dev->num_peers) {
			char *line;
			int ret = read_line(&line, argv[1]);
			if (ret == 0) {
				if (!parse_key(peer_from_offset(buf.dev, peer_offset)->preshared_key, line)) {
					free(line);
					goto error;
				}
				free(line);
			} else if (ret == 1) {
				free(line);
				buf.dev->flags |= WGPEER_REMOVE_PRESHARED_KEY;
			} else
				goto error;
			argv += 2;
			argc -= 2;
		} else {
			fprintf(stderr, "Invalid argument: %s\n", argv[0]);
			goto error;
		}
	}
	*device = buf.dev;
	return true;
error:
	free(buf.dev);
	return false;
}
