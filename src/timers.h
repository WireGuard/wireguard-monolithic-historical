/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef WGTIMERS_H
#define WGTIMERS_H

struct wireguard_peer;

void timers_init_peer(struct wireguard_peer *peer);
void timers_uninit_peer(struct wireguard_peer *peer);
void timers_uninit_peer_wait(struct wireguard_peer *peer);

void timers_data_sent(struct wireguard_peer *peer);
void timers_data_received(struct wireguard_peer *peer);
void timers_any_authenticated_packet_received(struct wireguard_peer *peer);
void timers_handshake_initiated(struct wireguard_peer *peer);
void timers_handshake_complete(struct wireguard_peer *peer);
void timers_ephemeral_key_created(struct wireguard_peer *peer);
void timers_any_authenticated_packet_traversal(struct wireguard_peer *peer);

#endif
