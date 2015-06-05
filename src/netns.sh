#!/bin/bash
[[ $UID != 0 ]] && exec sudo bash "$(readlink -f "$0")" "$@"
set -ex
cd "$(dirname "$(readlink -f "$0")")"

cleanup() {
	set +e
	ip link del dev wgnetns1
	ip link del dev wgnetns2
	ip netns exec wgnetns ip link del dev wgnetns2
	killall iperf3
	ip netns del wgnetns
	exit 0
}

trap cleanup EXIT

ip link add dev wgnetns1 type wireguard
ip link add dev wgnetns2 type wireguard

ip netns del wgnetns 2>/dev/null || true
ip netns add wgnetns
ip link set wgnetns2 netns wgnetns
ip netns exec wgnetns ip link set lo up

ip addr add 192.168.241.1/24 dev wgnetns1
ip netns exec wgnetns ip addr add 192.168.241.2/24 dev wgnetns2

key1="$(tools/wg genkey)"
key2="$(tools/wg genkey)"

tools/wg set wgnetns1 private-key <(echo "$key1") listen-port 38281 peer "$(tools/wg pubkey <<<"$key2")" allowed-ips 192.168.241.2/24 endpoint 127.0.0.1:43928
ip netns exec wgnetns tools/wg set wgnetns2 private-key <(echo "$key2") listen-port 43928 peer "$(tools/wg pubkey <<<"$key1")" allowed-ips 192.168.241.1/24 endpoint 127.0.0.1:38281

ip link set wgnetns1 up
ip netns exec wgnetns ip link set wgnetns2 up

ip netns exec wgnetns iperf3 -s -D
stdbuf -o 0 iperf3 -i 1 -n 300000G "$@" -c 192.168.241.2
