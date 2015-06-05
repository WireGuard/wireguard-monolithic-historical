#!/bin/bash
set -e

PRIVATE_KEYS=("")
PUBLIC_KEYS=("")

resetwg() {
	for i in {1..64}; do
		ip link delete dev wg${i} 2>/dev/null >/dev/null || true
	done
}

for i in {1..64}; do
	next_key="$(wg genkey)"
	PRIVATE_KEYS+=("$next_key")
	PUBLIC_KEYS+=($(wg pubkey <<<"$next_key"))
done

resetwg
trap resetwg INT TERM EXIT

for i in {1..64}; do
	{ echo "[Interface]"
	  echo "ListenPort = $(( $i + 31222 ))"
	  echo "PrivateKey = ${PRIVATE_KEYS[$i]}"

	for j in {1..64}; do
		[[ $i == $j ]] && continue
		echo "[Peer]"
		echo "PublicKey = ${PUBLIC_KEYS[$j]}"
		echo "AllowedIPs = 192.168.8.${j}/32"
		echo "Endpoint = 127.0.0.1:$(( $j + 31222 ))"
	  done
	} > "/tmp/deviceload.conf"

	ip link add dev wg${i} type wireguard
	wg setconf wg${i} "/tmp/deviceload.conf"
	ip link set up dev wg${i}
	rm "/tmp/deviceload.conf"
done

ip address add dev wg1 192.168.8.1/24

while true; do
	for i in {2..64}; do
		echo hello | ncat -u 192.168.8.${i} 1234
	done
done
