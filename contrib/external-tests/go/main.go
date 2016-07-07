/* Copyright 2015-2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/dchest/blake2s"
	"github.com/titanous/noise"
)

func main() {
	ourPrivate, _ := base64.StdEncoding.DecodeString("WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=")
	ourPublic, _ := base64.StdEncoding.DecodeString("K5sF9yESrSBsOXPd6TcpKNgqoy1Ik3ZFKl4FolzrRyI=")
	preshared, _ := base64.StdEncoding.DecodeString("FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=")
	theirPublic, _ := base64.StdEncoding.DecodeString("qRCwZSKInrMAq5sepfCdaCsRJaoLe5jhtzfiw7CjbwM=")
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	hs := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte("WireGuard v0 zx2c4 Jason@zx2c4.com"),
		PresharedKey:  preshared,
		StaticKeypair: noise.DHKey{Private: ourPrivate, Public: ourPublic},
		PeerStatic:    theirPublic,
	})
	conn, err := net.Dial("udp", "demo.wireguard.io:12913")
	if err != nil {
		log.Fatalf("error dialing udp socket: %s", err)
	}
	defer conn.Close()

	now := time.Now()
	tai64n := make([]byte, 12)
	binary.BigEndian.PutUint64(tai64n[:], uint64(now.Unix()))
	binary.BigEndian.PutUint32(tai64n[8:], uint32(now.UnixNano()))
	initiationPacket := make([]byte, 5)
	initiationPacket[0] = 1                                 // Type: Initiation
	binary.LittleEndian.PutUint32(initiationPacket[1:], 28) // Sender index: 28 (arbitrary)
	initiationPacket, _, _ = hs.WriteMessage(initiationPacket, tai64n)
	hasher, _ := blake2s.New(&blake2s.Config{Size: 16, Key: preshared})
	hasher.Write(theirPublic)
	hasher.Write(initiationPacket)
	initiationPacket = append(initiationPacket, hasher.Sum(nil)[:16]...)
	initiationPacket = append(initiationPacket, make([]byte, 16)...)
	if _, err := conn.Write(initiationPacket); err != nil {
		log.Fatalf("error writing initiation packet: %s", err)
	}

	responsePacket := make([]byte, 89)
	n, err := conn.Read(responsePacket)
	if err != nil {
		log.Fatalf("error reading response packet: %s", err)
	}
	if n != len(responsePacket) {
		log.Fatalf("response packet too short: want %d, got %d", len(responsePacket), n)
	}
	if responsePacket[0] != 2 { // Type: Response
		log.Fatalf("response packet type wrong: want %d, got %d", 2, responsePacket[0])
	}
	theirIndex := binary.LittleEndian.Uint32(responsePacket[1:])
	ourIndex := binary.LittleEndian.Uint32(responsePacket[5:])
	if ourIndex != 28 {
		log.Fatalf("response packet index wrong: want %d, got %d", 28, ourIndex)
	}
	payload, sendCipher, _, err := hs.ReadMessage(nil, responsePacket[9:57])
	if err != nil {
		log.Fatalf("error reading handshake message: %s", err)
	}
	if len(payload) > 0 {
		log.Fatalf("unexpected payload: %x", payload)
	}

	keepalivePacket := make([]byte, 13)
	keepalivePacket[0] = 4 // Type: Data
	binary.LittleEndian.PutUint32(keepalivePacket[1:], theirIndex)
	binary.LittleEndian.PutUint64(keepalivePacket[5:], 0) // Nonce
	keepalivePacket = sendCipher.Encrypt(keepalivePacket, nil, nil)
	if _, err := conn.Write(keepalivePacket); err != nil {
		log.Fatalf("error writing keepalive packet: %s", err)
	}
}
