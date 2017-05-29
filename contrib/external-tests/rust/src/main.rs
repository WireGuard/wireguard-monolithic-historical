/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

extern crate snow;
extern crate base64;
extern crate time;
extern crate byteorder;
extern crate crypto;

use byteorder::{ByteOrder, BigEndian, LittleEndian};
use crypto::blake2s::Blake2s;
use snow::NoiseBuilder;
use std::net::*;

static TEST_SERVER: &'static str = "demo.wireguard.io:12913";

fn memcpy(out: &mut [u8], data: &[u8]) {
	out[..data.len()].copy_from_slice(data);
}

fn main() {
	let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

	let their_public = base64::decode(&"qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=").unwrap();
	let my_private = base64::decode(&"WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=").unwrap();
	let my_preshared = base64::decode(&"FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=").unwrap();

	let mut noise = NoiseBuilder::new("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
		.local_private_key(&my_private[..])
		.remote_public_key(&their_public[..])
		.prologue("WireGuard v1 zx2c4 Jason@zx2c4.com".as_bytes())
		.psk(2, &my_preshared[..])
		.build_initiator().unwrap();

	let now = time::get_time();
	let mut tai64n = [0; 12];
	BigEndian::write_i64(&mut tai64n[0..], 4611686018427387914 + now.sec);
	BigEndian::write_i32(&mut tai64n[8..], now.nsec);
	let mut initiation_packet = [0; 148];
	initiation_packet[0] = 1; /* Type: Initiation */
	initiation_packet[1] = 0; /* Reserved */
	initiation_packet[2] = 0; /* Reserved */
	initiation_packet[3] = 0; /* Reserved */
	LittleEndian::write_u32(&mut initiation_packet[4..], 28); /* Sender index: 28 (arbitrary) */
	noise.write_message(&tai64n, &mut initiation_packet[8..]).unwrap();
	let mut mac_key_input = [0; 40];
	let mut mac_key = [0; 32];
	memcpy(&mut mac_key_input, b"mac1----");
	memcpy(&mut mac_key_input[8..], &their_public);
	Blake2s::blake2s(&mut mac_key, &mac_key_input, &[0; 0]);
	let mut mac = [0; 16];
	Blake2s::blake2s(&mut mac, &initiation_packet[0..116], &mac_key);
	memcpy(&mut initiation_packet[116..], &mac);
	socket.send_to(&initiation_packet, TEST_SERVER).unwrap();

	let mut response_packet = [0; 92];
	socket.recv_from(&mut response_packet).unwrap();
	assert!(response_packet[0] == 2 /* Type: Response */);
	assert!(response_packet[1] == 0 /* Reserved */);
	assert!(response_packet[2] == 0 /* Reserved */);
	assert!(response_packet[3] == 0 /* Reserved */);
	let their_index = LittleEndian::read_u32(&response_packet[4..]);
	let our_index = LittleEndian::read_u32(&response_packet[8..]);
	assert!(our_index == 28);
	let payload_len = noise.read_message(&response_packet[12..60], &mut []).unwrap();
	assert!(payload_len == 0);
	noise = noise.into_transport_mode().unwrap();

	let mut keepalive_packet = [0; 32];
	keepalive_packet[0] = 4; /* Type: Data */
	keepalive_packet[1] = 0; /* Reserved */
	keepalive_packet[2] = 0; /* Reserved */
	keepalive_packet[3] = 0; /* Reserved */
	LittleEndian::write_u32(&mut keepalive_packet[4..], their_index);
	LittleEndian::write_u64(&mut keepalive_packet[8..], 0);
	noise.write_message(&[], &mut keepalive_packet[16..]).unwrap(); /* Empty payload means keepalive */
	socket.send_to(&keepalive_packet, TEST_SERVER).unwrap();
}
