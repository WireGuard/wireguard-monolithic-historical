/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <netdb.h>

#include "ipc.h"
#include "subcommands.h"
#include "terminal.h"
#include "base64.h"
#include "../uapi.h"

static int peer_cmp(const void *first, const void *second)
{
	time_t diff;
	const struct wgpeer *a = *(const void **)first, *b = *(const void **)second;
	if (!a->last_handshake_time.tv_sec && !a->last_handshake_time.tv_usec && (b->last_handshake_time.tv_sec || b->last_handshake_time.tv_usec))
		return 1;
	if (!b->last_handshake_time.tv_sec && !b->last_handshake_time.tv_usec && (a->last_handshake_time.tv_sec || a->last_handshake_time.tv_usec))
		return -1;
	diff = a->last_handshake_time.tv_sec - b->last_handshake_time.tv_sec;
	if (!diff)
		diff = a->last_handshake_time.tv_usec - b->last_handshake_time.tv_usec;
	if (diff < 0)
		return 1;
	if (diff > 0)
		return -1;
	return 0;
}

static void sort_peers(struct wgdevice *device)
{
	uint8_t *new_device, *pos;
	struct wgpeer **peers;
	struct wgpeer *peer;
	size_t i, len;

	peers = calloc(device->num_peers, sizeof(struct wgpeer *));
	if (!peers)
		return;

	len = sizeof(struct wgdevice);
	for_each_wgpeer(device, peer, i)
		len += sizeof(struct wgpeer) + (peer->num_ipmasks * sizeof(struct wgipmask));
	pos = new_device = malloc(len);
	if (!new_device) {
		free(peers);
		return;
	}

	memcpy(pos, device, sizeof(struct wgdevice));
	pos += sizeof(struct wgdevice);

	for_each_wgpeer(device, peer, i)
		peers[i] = peer;

	qsort(peers, device->num_peers, sizeof(struct wgpeer *), peer_cmp);
	for (i = 0; i < device->num_peers; ++i) {
		len = sizeof(struct wgpeer) + (peers[i]->num_ipmasks * sizeof(struct wgipmask));
		memcpy(pos, peers[i], len);
		pos += len;
	}
	free(peers);

	memcpy(device, new_device, pos - new_device);
	free(new_device);
}

static const uint8_t zero[WG_KEY_LEN] = { 0 };

static char *key(const uint8_t key[static WG_KEY_LEN])
{
	static char base64[WG_KEY_LEN_BASE64];
	if (!memcmp(key, zero, WG_KEY_LEN))
		return "(none)";
	key_to_base64(base64, key);
	return base64;
}

static char *masked_key(const uint8_t masked_key[static WG_KEY_LEN])
{
	const char *var = getenv("WG_HIDE_KEYS");
	if (var && !strcmp(var, "never"))
		return key(masked_key);
	return "(hidden)";
}

static char *ip(const struct wgipmask *ip)
{
	static char buf[INET6_ADDRSTRLEN + 1];
	memset(buf, 0, INET6_ADDRSTRLEN + 1);
	if (ip->family == AF_INET)
		inet_ntop(AF_INET, &ip->ip4, buf, INET6_ADDRSTRLEN);
	else if (ip->family == AF_INET6)
		inet_ntop(AF_INET6, &ip->ip6, buf, INET6_ADDRSTRLEN);
	return buf;
}

static char *endpoint(const struct sockaddr *addr)
{
	char host[4096 + 1];
	char service[512 + 1];
	static char buf[sizeof(host) + sizeof(service) + 4];
	int ret;
	socklen_t addr_len = 0;

	memset(buf, 0, sizeof(buf));
	if (addr->sa_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else if (addr->sa_family == AF_INET6)
		addr_len = sizeof(struct sockaddr_in6);

	ret = getnameinfo(addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST);
	if (ret)
		strncpy(buf, gai_strerror(ret), sizeof(buf) - 1);
	else
		snprintf(buf, sizeof(buf) - 1, (addr->sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s", host, service);
	return buf;
}

static size_t pretty_time(char *buf, const size_t len, unsigned long long left)
{
	size_t offset = 0;
	unsigned long long years, days, hours, minutes, seconds;

	years = left / (365 * 24 * 60 * 60);
	left = left % (365 * 24 * 60 * 60);
	days = left / (24 * 60 * 60);
	left = left % (24 * 60 * 60);
	hours = left / (60 * 60);
	left = left % (60 * 60);
	minutes = left / 60;
	seconds = left % 60;

	if (years)
		offset += snprintf(buf + offset, len - offset - 1, "%s%llu " TERMINAL_FG_CYAN "year%s" TERMINAL_RESET, offset ? ", " : "", years, years == 1 ? "" : "s");
	if (days)
		offset += snprintf(buf + offset, len - offset - 1, "%s%llu " TERMINAL_FG_CYAN  "day%s" TERMINAL_RESET, offset ? ", " : "", days, days == 1 ? "" : "s");
	if (hours)
		offset += snprintf(buf + offset, len - offset - 1, "%s%llu " TERMINAL_FG_CYAN  "hour%s" TERMINAL_RESET, offset ? ", " : "", hours, hours == 1 ? "" : "s");
	if (minutes)
		offset += snprintf(buf + offset, len - offset - 1, "%s%llu " TERMINAL_FG_CYAN "minute%s" TERMINAL_RESET, offset ? ", " : "", minutes, minutes == 1 ? "" : "s");
	if (seconds)
		offset += snprintf(buf + offset, len - offset - 1, "%s%llu " TERMINAL_FG_CYAN  "second%s" TERMINAL_RESET, offset ? ", " : "", seconds, seconds == 1 ? "" : "s");

	return offset;
}

static char *ago(const struct timeval *t)
{
	static char buf[1024];
	size_t offset;
	time_t now = time(NULL);

	if (now == t->tv_sec)
		strncpy(buf, "Now", sizeof(buf) - 1);
	else if (now < t->tv_sec)
		strncpy(buf, "(" TERMINAL_FG_RED "System clock wound backward; connection problems may ensue." TERMINAL_RESET ")", sizeof(buf) - 1);
	else {
		offset = pretty_time(buf, sizeof(buf), now - t->tv_sec);
		strncpy(buf + offset, " ago", sizeof(buf) - offset - 1);
	}

	return buf;
}

static char *every(uint16_t seconds)
{
	static char buf[1024] = "every ";
	pretty_time(buf + strlen("every "), sizeof(buf) - strlen("every ") - 1, seconds);
	return buf;
}

static char *bytes(uint64_t b)
{
	static char buf[1024];

	if (b < 1024ULL)
		snprintf(buf, sizeof(buf) - 1, "%u " TERMINAL_FG_CYAN "B" TERMINAL_RESET, (unsigned)b);
	else if (b < 1024ULL * 1024ULL)
		snprintf(buf, sizeof(buf) - 1, "%.2f " TERMINAL_FG_CYAN "KiB" TERMINAL_RESET, (double)b / 1024);
	else if (b < 1024ULL * 1024ULL * 1024ULL)
		snprintf(buf, sizeof(buf) - 1, "%.2f " TERMINAL_FG_CYAN "MiB" TERMINAL_RESET, (double)b / (1024 * 1024));
	else if (b < 1024ULL * 1024ULL * 1024ULL * 1024ULL)
		snprintf(buf, sizeof(buf) - 1, "%.2f " TERMINAL_FG_CYAN "GiB" TERMINAL_RESET, (double)b / (1024 * 1024 * 1024));
	else
		snprintf(buf, sizeof(buf) - 1, "%.2f " TERMINAL_FG_CYAN "TiB" TERMINAL_RESET, (double)b / (1024 * 1024 * 1024) / 1024);

	return buf;
}

static const char *COMMAND_NAME = NULL;
static void show_usage(void)
{
	fprintf(stderr, "Usage: %s %s { <interface> | all | interfaces } [public-key | private-key | listen-port | fwmark | peers | preshared-keys | endpoints | allowed-ips | latest-handshakes | transfer | persistent-keepalive | dump]\n", PROG_NAME, COMMAND_NAME);
}

static void pretty_print(struct wgdevice *device)
{
	size_t i, j;
	struct wgpeer *peer;
	struct wgipmask *ipmask;

	terminal_printf(TERMINAL_RESET);
	terminal_printf(TERMINAL_FG_GREEN TERMINAL_BOLD "interface" TERMINAL_RESET ": " TERMINAL_FG_GREEN "%s" TERMINAL_RESET "\n", device->interface);
	if (memcmp(device->public_key, zero, WG_KEY_LEN))
		terminal_printf("  " TERMINAL_BOLD "public key" TERMINAL_RESET ": %s\n", key(device->public_key));
	if (memcmp(device->private_key, zero, WG_KEY_LEN))
		terminal_printf("  " TERMINAL_BOLD "private key" TERMINAL_RESET ": %s\n", masked_key(device->private_key));
	if (device->port)
		terminal_printf("  " TERMINAL_BOLD "listening port" TERMINAL_RESET ": %u\n", device->port);
	if (device->fwmark)
		terminal_printf("  " TERMINAL_BOLD "fwmark" TERMINAL_RESET ": 0x%x\n", device->fwmark);
	if (device->num_peers) {
		sort_peers(device);
		terminal_printf("\n");
	}
	for_each_wgpeer(device, peer, i) {
		terminal_printf(TERMINAL_FG_YELLOW TERMINAL_BOLD "peer" TERMINAL_RESET ": " TERMINAL_FG_YELLOW "%s" TERMINAL_RESET "\n", key(peer->public_key));
		if (memcmp(peer->preshared_key, zero, WG_KEY_LEN))
			terminal_printf("  " TERMINAL_BOLD "preshared key" TERMINAL_RESET ": %s\n", masked_key(peer->preshared_key));
		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
			terminal_printf("  " TERMINAL_BOLD "endpoint" TERMINAL_RESET ": %s\n", endpoint(&peer->endpoint.addr));
		terminal_printf("  " TERMINAL_BOLD "allowed ips" TERMINAL_RESET ": ");
		if (peer->num_ipmasks) {
			for_each_wgipmask(peer, ipmask, j)
				terminal_printf("%s" TERMINAL_FG_CYAN "/" TERMINAL_RESET "%u%s", ip(ipmask), ipmask->cidr, j == (size_t)peer->num_ipmasks - 1 ? "\n" : ", ");
		} else
			terminal_printf("(none)\n");
		if (peer->last_handshake_time.tv_sec)
			terminal_printf("  " TERMINAL_BOLD "latest handshake" TERMINAL_RESET ": %s\n", ago(&peer->last_handshake_time));
		if (peer->rx_bytes || peer->tx_bytes) {
			terminal_printf("  " TERMINAL_BOLD "transfer" TERMINAL_RESET ": ");
			terminal_printf("%s received, ", bytes(peer->rx_bytes));
			terminal_printf("%s sent\n", bytes(peer->tx_bytes));
		}
		if (peer->persistent_keepalive_interval)
			terminal_printf("  " TERMINAL_BOLD "persistent keepalive" TERMINAL_RESET ": %s\n", every(peer->persistent_keepalive_interval));
		if (i + 1 < device->num_peers)
			terminal_printf("\n");
	}
}

static void dump_print(struct wgdevice *device, bool with_interface)
{
	size_t i, j;
	struct wgpeer *peer;
	struct wgipmask *ipmask;

	if (with_interface)
		printf("%s\t", device->interface);
	printf("%s\t", key(device->private_key));
	printf("%s\t", key(device->public_key));
	printf("%u\t", device->port);
	if (device->fwmark)
		printf("0x%x\n", device->fwmark);
	else
		printf("off\n");
	for_each_wgpeer(device, peer, i) {
		if (with_interface)
			printf("%s\t", device->interface);
		printf("%s\t", key(peer->public_key));
		printf("%s\t", key(peer->preshared_key));
		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
			printf("%s\t", endpoint(&peer->endpoint.addr));
		else
			printf("(none)\t");
		if (peer->num_ipmasks) {
			for_each_wgipmask(peer, ipmask, j)
				printf("%s/%u%c", ip(ipmask), ipmask->cidr, j == (size_t)peer->num_ipmasks - 1 ? '\t' : ',');
		} else
			printf("(none)\t");
		printf("%llu\t", (unsigned long long)peer->last_handshake_time.tv_sec);
		printf("%" PRIu64 "\t%" PRIu64 "\t", (uint64_t)peer->rx_bytes, (uint64_t)peer->tx_bytes);
		if (peer->persistent_keepalive_interval)
			printf("%u\n", peer->persistent_keepalive_interval);
		else
			printf("off\n");
	}
}

static bool ugly_print(struct wgdevice *device, const char *param, bool with_interface)
{
	size_t i, j;
	struct wgpeer *peer;
	struct wgipmask *ipmask;
	if (!strcmp(param, "public-key")) {
		if (with_interface)
			printf("%s\t", device->interface);
		printf("%s\n", key(device->public_key));
	} else if (!strcmp(param, "private-key")) {
		if (with_interface)
			printf("%s\t", device->interface);
		printf("%s\n", key(device->private_key));
	} else if (!strcmp(param, "listen-port")) {
		if (with_interface)
			printf("%s\t", device->interface);
		printf("%u\n", device->port);
	} else if (!strcmp(param, "fwmark")) {
		if (with_interface)
			printf("%s\t", device->interface);
		if (device->fwmark)
			printf("0x%x\n", device->fwmark);
		else
			printf("off\n");
	} else if (!strcmp(param, "endpoints")) {
		if (with_interface)
			printf("%s\t", device->interface);
		for_each_wgpeer(device, peer, i) {
			printf("%s\t", key(peer->public_key));
			if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6)
				printf("%s\n", endpoint(&peer->endpoint.addr));
			else
				printf("(none)\n");
		}
	} else if (!strcmp(param, "allowed-ips")) {
		for_each_wgpeer(device, peer, i) {
			if (with_interface)
				printf("%s\t", device->interface);
			printf("%s\t", key(peer->public_key));
			if (peer->num_ipmasks) {
				for_each_wgipmask(peer, ipmask, j)
					printf("%s/%u%c", ip(ipmask), ipmask->cidr, j == (size_t)peer->num_ipmasks - 1 ? '\n' : ' ');
			} else
				printf("(none)\n");
		}
	} else if (!strcmp(param, "latest-handshakes")) {
		for_each_wgpeer(device, peer, i) {
			if (with_interface)
				printf("%s\t", device->interface);
			printf("%s\t%llu\n", key(peer->public_key), (unsigned long long)peer->last_handshake_time.tv_sec);
		}
	} else if (!strcmp(param, "transfer")) {
		for_each_wgpeer(device, peer, i) {
			if (with_interface)
				printf("%s\t", device->interface);
			printf("%s\t%" PRIu64 "\t%" PRIu64 "\n", key(peer->public_key), (uint64_t)peer->rx_bytes, (uint64_t)peer->tx_bytes);
		}
	} else if (!strcmp(param, "persistent-keepalive")) {
		for_each_wgpeer(device, peer, i) {
			if (with_interface)
				printf("%s\t", device->interface);
			if (peer->persistent_keepalive_interval)
				printf("%s\t%u\n", key(peer->public_key), peer->persistent_keepalive_interval);
			else
				printf("%s\toff\n", key(peer->public_key));
		}
	} else if (!strcmp(param, "preshared-keys")) {
		for_each_wgpeer(device, peer, i) {
			if (with_interface)
				printf("%s\t", device->interface);
			printf("%s\t", key(peer->public_key));
			printf("%s\n", key(peer->preshared_key));
		}
	} else if (!strcmp(param, "peers")) {
		for_each_wgpeer(device, peer, i) {
			if (with_interface)
				printf("%s\t", device->interface);
			printf("%s\n", key(peer->public_key));
		}
	} else if (!strcmp(param, "dump"))
		dump_print(device, with_interface);
	else {
		fprintf(stderr, "Invalid parameter: `%s`\n", param);
		show_usage();
		return false;
	}
	return true;
}

int show_main(int argc, char *argv[])
{
	int ret = 0;
	COMMAND_NAME = argv[0];

	if (argc > 3) {
		show_usage();
		return 1;
	}

	if (argc == 1 || !strcmp(argv[1], "all")) {
		char *interfaces = ipc_list_devices(), *interface;
		if (!interfaces) {
			perror("Unable to get devices");
			return 1;
		}
		interface = interfaces;
		for (size_t len = 0; (len = strlen(interface)); interface += len + 1) {
			struct wgdevice *device = NULL;
			if (ipc_get_device(&device, interface) < 0) {
				perror("Unable to get device");
				continue;
			}
			if (argc == 3) {
				if (!ugly_print(device, argv[2], true)) {
					ret = 1;
					free(device);
					break;
				}
			} else {
				pretty_print(device);
				if (strlen(interface + len + 1))
					printf("\n");
			}
			free(device);
		}
		free(interfaces);
	} else if (!strcmp(argv[1], "interfaces")) {
		char *interfaces, *interface;
		if (argc > 2) {
			show_usage();
			return 1;
		}
		interfaces = ipc_list_devices();
		if (!interfaces) {
			perror("Unable to get devices");
			return 1;
		}
		interface = interfaces;
		for (size_t len = 0; (len = strlen(interface)); interface += len + 1)
			printf("%s%c", interface, strlen(interface + len + 1) ? ' ' : '\n');
		free(interfaces);
	} else if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")))
		show_usage();
	else {
		struct wgdevice *device = NULL;
		if (!ipc_has_device(argv[1])) {
			fprintf(stderr, "`%s` is not a valid WireGuard interface\n", argv[1]);
			show_usage();
			return 1;
		}
		if (ipc_get_device(&device, argv[1]) < 0) {
			perror("Unable to get device");
			show_usage();
			return 1;
		}
		if (argc == 3) {
			if (!ugly_print(device, argv[2], false))
				ret = 1;
		} else
			pretty_print(device);
		free(device);
	}
	return ret;
}
