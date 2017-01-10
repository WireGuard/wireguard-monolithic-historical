/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

extern crate screech;
extern crate crypto;
extern crate time;
extern crate rustc_serialize;
extern crate byteorder;

use screech::*;
use byteorder::{ByteOrder, BigEndian, LittleEndian};
use crypto::curve25519::curve25519_base;
use crypto::blake2s::Blake2s;
use rustc_serialize::base64::FromBase64;
use std::net::*;

fn memcpy(out: &mut [u8], data: &[u8]) {
	for count in 0..data.len() {
		out[count] = data[count];
	}
}

fn main() {
	let send_addr = "demo.wireguard.io:12913".to_socket_addrs().unwrap().next().unwrap();
	let listen_addr = "0.0.0.0:0".to_socket_addrs().unwrap().next().unwrap();
	let socket = UdpSocket::bind(listen_addr).unwrap();
	let mut empty_payload = [0; 0];

	let mut their_public = [0; 32];
	memcpy(&mut their_public, &"qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=".from_base64().unwrap());
	let mut my_private = [0; 32];
	memcpy(&mut my_private, &"WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=".from_base64().unwrap());
	let mut my_preshared = [0; 32];
	memcpy(&mut my_preshared, &"FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=".from_base64().unwrap());
	let my_public = curve25519_base(&my_private);
	let mut my_keypair : Dh25519 = Default::default();
	my_keypair.set(&my_private, &my_public);
	let mut owner : HandshakeCryptoOwner<RandomOs, Dh25519, CipherChaChaPoly, HashBLAKE2s> = Default::default();
	owner.set_s(my_keypair);
	owner.set_rs(&their_public);
	let mut cipherstate1 : CipherState<CipherChaChaPoly> = Default::default();
        let mut cipherstate2 : CipherState<CipherChaChaPoly> = Default::default();
	let mut handshake = HandshakeState::new_from_owner(&mut owner, true, HandshakePattern::IK, "WireGuard v0 zx2c4 Jason@zx2c4.com".as_bytes(), Some(&my_preshared[..]), &mut cipherstate1, &mut cipherstate2);

	let now = time::get_time();
	let mut tai64n = [0; 12];
	BigEndian::write_i64(&mut tai64n[0..], 4611686018427387914ULL + now.sec);
	BigEndian::write_i32(&mut tai64n[8..], now.nsec);
	let mut initiation_packet = [0; 148];
	initiation_packet[0] = 1; /* Type: Initiation */
	initiation_packet[1] = 0; /* Reserved */
	initiation_packet[2] = 0; /* Reserved */
	initiation_packet[3] = 0; /* Reserved */
	LittleEndian::write_u32(&mut initiation_packet[4..], 28); /* Sender index: 28 (arbitrary) */
	handshake.write_message(&tai64n, &mut initiation_packet[8..]);
	let mut mac_material = [0; 148];
	memcpy(&mut mac_material, &their_public);
	memcpy(&mut mac_material[32..], &initiation_packet[0..116]);
	let mut mac = [0; 16];
	Blake2s::blake2s(&mut mac, &mac_material, &my_preshared);
	memcpy(&mut initiation_packet[116..], &mac);
	socket.send_to(&initiation_packet, &send_addr).unwrap();

	let mut response_packet = [0; 92];
	socket.recv_from(&mut response_packet).unwrap();
	assert!(response_packet[0] == 2 /* Type: Response */);
	assert!(response_packet[1] == 0 /* Reserved */);
	assert!(response_packet[2] == 0 /* Reserved */);
	assert!(response_packet[3] == 0 /* Reserved */);
	let their_index = LittleEndian::read_u32(&response_packet[4..]);
	let our_index = LittleEndian::read_u32(&response_packet[8..]);
	assert!(our_index == 28);
	let (payload_len, last) = handshake.read_message(&response_packet[12..60], &mut empty_payload).unwrap();
	assert!(payload_len == 0 && last);

	let mut keepalive_packet = [0; 32];
	keepalive_packet[0] = 4; /* Type: Data */
	keepalive_packet[1] = 0; /* Reserved */
	keepalive_packet[2] = 0; /* Reserved */
	keepalive_packet[3] = 0; /* Reserved */
	LittleEndian::write_u32(&mut keepalive_packet[4..], their_index);
	LittleEndian::write_u64(&mut keepalive_packet[8..], cipherstate1.n);
	cipherstate1.encrypt(&empty_payload, &mut keepalive_packet[16..]); /* Empty payload means keepalive */
	socket.send_to(&keepalive_packet, &send_addr).unwrap();
}
