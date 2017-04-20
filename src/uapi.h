/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Userspace API for WireGuard
 * ---------------------------
 *
 * ioctl(WG_GET_DEVICE, { .ifr_name: "wg0", .ifr_data: NULL }):
 *
 *     Returns the number of bytes required to hold the peers of a device (`ret_peers_size`).
 *
 * ioctl(WG_GET_DEVICE, { .ifr_name: "wg0", .ifr_data: user_pointer }):
 *
 *     Retrevies device info, peer info, and ipmask info.
 *
 *     `user_pointer` must point to a region of memory of size `sizeof(struct wgdevice) + ret_peers_size`
 *     and containing the structure `struct wgdevice { .peers_size: ret_peers_size }`.
 *
 *     Writes to `user_pointer` a succession of structs:
 *
 *         struct wgdevice { .num_peers = 3 }
 *             struct wgpeer { .num_ipmasks = 4 }
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 2 }
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 0 }
 *
 *     Returns 0 on success. Returns -EMSGSIZE if there is too much data for the size of passed-in
 *     memory, in which case, this should be recalculated using the call above. Returns -errno if
 *     another error occured.
 *
 * ioctl(WG_SET_DEVICE, { .ifr_name: "wg0", .ifr_data: user_pointer }):
 *
 *     Sets device info, peer info, and ipmask info.
 *
 *     `user_pointer` must point to a region of memory containing a succession of structs:
 *
 *         struct wgdevice { .num_peers = 3 }
 *             struct wgpeer { .num_ipmasks = 4 }
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 2 }
 *                 struct wgipmask
 *                 struct wgipmask
 *             struct wgpeer { .num_ipmasks = 0 }
 *
 *     If `wgdevice->flags & WGDEVICE_REPLACE_PEERS` is true, removes all peers of device before adding new ones.
 *     If `wgpeer->flags & WGPEER_REMOVE_ME` is true, the peer identified by `wgpeer->public_key` is removed.
 *     If `wgpeer->flags & WGPEER_REPLACE_IPMASKS` is true, removes all ipmasks before adding new ones.
 *     If `wgdevice->private_key` is filled with zeros, no action is taken on the private key.
 *     If `wgdevice->preshared_key` is filled with zeros, no action is taken on the preshared key.
 *     If `wgdevice->flags & WGDEVICE_REMOVE_PRIVATE_KEY` is true, the private key is removed.
 *     If `wgdevice->flags & WGDEVICE_REMOVE_PRESHARED_KEY` is true, the preshared key is removed.
 *
 *     Returns 0 on success, or -errno if an error occurred.
 */


#ifndef WGUAPI_H
#define WGUAPI_H

#ifdef __linux__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
#endif
#ifdef __KERNEL__
#include <linux/time.h>
#include <linux/socket.h>
#else
#include <net/if.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>
#endif

#define WG_GET_DEVICE (SIOCDEVPRIVATE + 0)
#define WG_SET_DEVICE (SIOCDEVPRIVATE + 1)

#define WG_KEY_LEN 32

struct wgipmask {
	__s32 family;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	};
	__u8 cidr;
};

enum {
	WGPEER_REMOVE_ME = (1 << 0),
	WGPEER_REPLACE_IPMASKS = (1 << 1)
};
struct wgpeer {
	__u8 public_key[WG_KEY_LEN]; /* Get/Set */
	__u32 flags; /* Set */

	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} endpoint; /* Get/Set */

	struct timeval last_handshake_time; /* Get */
	__u64 rx_bytes, tx_bytes; /* Get */
	__u16 persistent_keepalive_interval; /* Get/Set -- 0 = off, 0xffff = unset */

	__u16 num_ipmasks; /* Get/Set */
};

enum {
	WGDEVICE_REPLACE_PEERS = (1 << 0),
	WGDEVICE_REMOVE_PRIVATE_KEY = (1 << 1),
	WGDEVICE_REMOVE_PRESHARED_KEY = (1 << 2),
	WGDEVICE_REMOVE_FWMARK = (1 << 3)
};

enum {
	WG_API_VERSION_MAGIC = 0xbeef0001
};

struct wgdevice {
	__u32 version_magic; /* Must be value of WG_API_VERSION_MAGIC */
	char interface[IFNAMSIZ]; /* Get */
	__u32 flags; /* Set */

	__u8 public_key[WG_KEY_LEN]; /* Get */
	__u8 private_key[WG_KEY_LEN]; /* Get/Set */
	__u8 preshared_key[WG_KEY_LEN]; /* Get/Set */
	__u32 fwmark; /* Get/Set */
	__u16 port; /* Get/Set */

	union {
		__u16 num_peers; /* Get/Set */
		__u32 peers_size; /* Get */
	};
};

/* These are simply for convenience in iterating. It allows you to write something like:
 *
 *    for_each_wgpeer(device, peer, i) {
 *        for_each_wgipmask(peer, ipmask, j) {
 *            do_something_with_ipmask(ipmask);
 *        }
 *     }
 */
#define for_each_wgpeer(__dev, __peer, __i) for ((__i) = 0, (__peer) = (struct wgpeer *)((uint8_t *)(__dev) + sizeof(struct wgdevice)); \
						 (__i) < (__dev)->num_peers; \
						 ++(__i), (__peer) = (struct wgpeer *)((uint8_t *)(__peer) + sizeof(struct wgpeer) + (sizeof(struct wgipmask) * (__peer)->num_ipmasks)))

#define for_each_wgipmask(__peer, __ipmask, __i) for ((__i) = 0, (__ipmask) = (struct wgipmask *)((uint8_t *)(__peer) + sizeof(struct wgpeer)); \
						 (__i) < (__peer)->num_ipmasks; \
						 ++(__i), (__ipmask) = (struct wgipmask *)((uint8_t *)(__ipmask) + sizeof(struct wgipmask)))

#endif
