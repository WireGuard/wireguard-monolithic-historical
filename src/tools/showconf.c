/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

#include "subcommands.h"
#include "base64.h"
#include "ipc.h"
#include "../uapi.h"

int showconf_main(int argc, char *argv[])
{
	static const uint8_t zero[WG_KEY_LEN] = { 0 };
	char base64[WG_KEY_LEN_BASE64];
	char ip[INET6_ADDRSTRLEN];
	struct wgdevice *device = NULL;
	struct wgpeer *peer;
	struct wgipmask *ipmask;
	size_t i, j;
	int ret = 1;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s %s <interface>\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (!ipc_has_device(argv[1])) {
		fprintf(stderr, "`%s` is not a valid WireGuard interface\n", argv[1]);
		fprintf(stderr, "Usage: %s %s <interface>\n", PROG_NAME, argv[0]);
		return 1;
	}

	if (ipc_get_device(&device, argv[1])) {
		perror("Unable to get device");
		goto cleanup;
	}

	printf("[Interface]\n");
	if (device->port)
		printf("ListenPort = %u\n", device->port);
	if (device->fwmark)
		printf("FwMark = 0x%x\n", device->fwmark);
	if (memcmp(device->private_key, zero, WG_KEY_LEN)) {
		key_to_base64(base64, device->private_key);
		printf("PrivateKey = %s\n", base64);
	}
	if (memcmp(device->preshared_key, zero, WG_KEY_LEN)) {
		key_to_base64(base64, device->preshared_key);
		printf("PresharedKey = %s\n", base64);
	}
	printf("\n");
	for_each_wgpeer(device, peer, i) {
		key_to_base64(base64, peer->public_key);
		printf("[Peer]\nPublicKey = %s\n", base64);
		if (peer->num_ipmasks)
			printf("AllowedIPs = ");
		for_each_wgipmask(peer, ipmask, j) {
			if (ipmask->family == AF_INET) {
				if (!inet_ntop(AF_INET, &ipmask->ip4, ip, INET6_ADDRSTRLEN))
					continue;
			} else if (ipmask->family == AF_INET6) {
				if (!inet_ntop(AF_INET6, &ipmask->ip6, ip, INET6_ADDRSTRLEN))
					continue;
			} else
				continue;
			printf("%s/%d", ip, ipmask->cidr);
			if (j + 1 < (size_t)peer->num_ipmasks)
				printf(", ");
		}
		if (peer->num_ipmasks)
			printf("\n");

		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6) {
			char host[4096 + 1];
			char service[512 + 1];
			static char buf[sizeof(host) + sizeof(service) + 4];
			socklen_t addr_len = 0;
			memset(buf, 0, sizeof(buf));
			if (peer->endpoint.addr.sa_family == AF_INET)
				addr_len = sizeof(struct sockaddr_in);
			else if (peer->endpoint.addr.sa_family == AF_INET6)
				addr_len = sizeof(struct sockaddr_in6);
			if (!getnameinfo(&peer->endpoint.addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST)) {
				snprintf(buf, sizeof(buf) - 1, (peer->endpoint.addr.sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s", host, service);
				printf("Endpoint = %s\n", buf);
			}
		}

		if (peer->persistent_keepalive_interval)
			printf("PersistentKeepalive = %u\n", peer->persistent_keepalive_interval);

		if (i + 1 < device->num_peers)
			printf("\n");
	}
	ret = 0;

cleanup:
	free(device);
	return ret;
}
