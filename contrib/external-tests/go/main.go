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
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func ipChecksum(buf []byte) uint16 {
	sum := uint32(0)
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

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

	// write handshake initiation packet
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

	// read handshake response packet
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
	payload, sendCipher, receiveCipher, err := hs.ReadMessage(nil, responsePacket[9:57])
	if err != nil {
		log.Fatalf("error reading handshake message: %s", err)
	}
	if len(payload) > 0 {
		log.Fatalf("unexpected payload: %x", payload)
	}

	// write ICMP Echo packet
	pingMessage, _ := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("WireGuard"),
		},
	}).Marshal(nil)
	pingHeader, err := (&ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(pingMessage),
		Protocol: 1, // ICMP
		TTL:      20,
		Src:      net.IPv4(10, 189, 129, 2),
		Dst:      net.IPv4(10, 189, 129, 1),
	}).Marshal()
	binary.BigEndian.PutUint16(pingHeader[2:], uint16(ipv4.HeaderLen+len(pingMessage))) // fix the length endianness on BSDs
	binary.BigEndian.PutUint16(pingHeader[10:], ipChecksum(append(pingHeader, pingMessage...)))
	if err != nil {
		panic(err)
	}
	pingPacket := make([]byte, 13)
	pingPacket[0] = 4 // Type: Data
	binary.LittleEndian.PutUint32(pingPacket[1:], theirIndex)
	binary.LittleEndian.PutUint64(pingPacket[5:], 0) // Nonce
	pingPacket = sendCipher.Encrypt(pingPacket, nil, append(pingHeader, pingMessage...))
	if _, err := conn.Write(pingPacket); err != nil {
		log.Fatalf("error writing ping message: %s", err)
	}

	// read ICMP Echo Reply packet
	replyPacket := make([]byte, 128)
	n, err = conn.Read(replyPacket)
	if err != nil {
		log.Fatalf("error reading ping reply message: %s", err)
	}
	replyPacket = replyPacket[:n]
	if replyPacket[0] != 4 { // Type: Data
		log.Fatalf("unexpected reply packet type: %d", replyPacket[0])
	}
	replyPacket, err = receiveCipher.Decrypt(nil, nil, replyPacket[13:])
	if err != nil {
		log.Fatalf("error decrypting reply packet: %s", err)
	}
	replyHeaderLen := int(replyPacket[0]&0x0f) << 2
	replyLen := binary.BigEndian.Uint16(replyPacket[2:])
	replyMessage, err := icmp.ParseMessage(1, replyPacket[replyHeaderLen:replyLen])
	if err != nil {
		log.Fatalf("error parsing echo: %s", err)
	}
	echo, ok := replyMessage.Body.(*icmp.Echo)
	if !ok {
		log.Fatalf("unexpected reply body type %T", replyMessage.Body)
	}

	if echo.ID != 1 || echo.Seq != 1 || string(echo.Data) != "WireGuard" {
		log.Fatalf("incorrect echo response: %#v", echo)
	}
}
