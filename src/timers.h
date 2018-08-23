/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_TIMERS_H
#define _WG_TIMERS_H

#include <linux/ktime.h>

struct wireguard_peer;

void timers_init(struct wireguard_peer *peer);
void timers_stop(struct wireguard_peer *peer);
void timers_data_sent(struct wireguard_peer *peer);
void timers_data_received(struct wireguard_peer *peer);
void timers_any_authenticated_packet_sent(struct wireguard_peer *peer);
void timers_any_authenticated_packet_received(struct wireguard_peer *peer);
void timers_handshake_initiated(struct wireguard_peer *peer);
void timers_handshake_complete(struct wireguard_peer *peer);
void timers_session_derived(struct wireguard_peer *peer);
void timers_any_authenticated_packet_traversal(struct wireguard_peer *peer);

static inline bool has_expired(u64 birthday_nanoseconds, u64 expiration_seconds)
{
	return (s64)(birthday_nanoseconds + expiration_seconds * NSEC_PER_SEC)
		<= (s64)ktime_get_boot_fast_ns();
}

#endif /* _WG_TIMERS_H */
