/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

package main

import (
	"github.com/titanous/noise"
	"net"
	"time"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"github.com/dchest/blake2s"
)

func assert(exp bool) {
	if !exp {
		panic("Assertion failed.")
	}
}

func main() {
	my_private, _ := base64.StdEncoding.DecodeString("WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=")
	my_public, _ := base64.StdEncoding.DecodeString("K5sF9yESrSBsOXPd6TcpKNgqoy1Ik3ZFKl4FolzrRyI=")
	preshared, _ := base64.StdEncoding.DecodeString("FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=")
	their_public, _ := base64.StdEncoding.DecodeString("qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=")
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs := noise.NewHandshakeState(noise.Config{CipherSuite: cs, Random: rand.Reader, Pattern: noise.HandshakeIK, Initiator: true, Prologue: []byte("WireGuard v0 zx2c4 Jason@zx2c4.com"), PresharedKey: preshared, StaticKeypair: noise.DHKey{Private: my_private, Public: my_public}, PeerStatic: their_public})
	conn, _ := net.Dial("udp", "test.wireguard.io:51820")

	now := time.Now()
	tai64n := make([]byte, 12)
	binary.BigEndian.PutUint64(tai64n[:], uint64(now.Unix()))
	binary.BigEndian.PutUint32(tai64n[8:], uint32(now.UnixNano()))
	initiation_packet := make([]byte, 5)
	initiation_packet[0] = 1 /* Type: Initiation */
	binary.LittleEndian.PutUint32(initiation_packet[1:], 28) /* Sender index: 28 (arbitrary) */
	initiation_packet, _, _ = hs.WriteMessage(initiation_packet, tai64n)
	hasher, _ := blake2s.New(&blake2s.Config{Size: 16, Key: preshared})
	hasher.Write(their_public)
	hasher.Write(initiation_packet)
	initiation_packet = append(initiation_packet, hasher.Sum(nil)[:16]...)
	initiation_packet = append(initiation_packet, bytes.Repeat([]byte{ 0 }, 16)...)
	conn.Write(initiation_packet)

	response_packet := make([]byte, 89)
	conn.Read(response_packet)
	assert(response_packet[0] == 2 /* Type: Response */)
	their_index := binary.LittleEndian.Uint32(response_packet[1:])
	our_index := binary.LittleEndian.Uint32(response_packet[5:])
	assert(our_index == 28)
	payload, send_cs, _, err := hs.ReadMessage(nil, response_packet[9:57])
	assert(len(payload) == 0 && err == nil)

	keepalive_packet := make([]byte, 13)
	keepalive_packet[0] = 4 /* Type: Data */
	binary.LittleEndian.PutUint32(keepalive_packet[1:], their_index)
	binary.LittleEndian.PutUint64(keepalive_packet[3:], 0) /* Nonce */
	keepalive_packet = send_cs.Encrypt(keepalive_packet, nil, nil)
	conn.Write(keepalive_packet)

	conn.Close()
}
