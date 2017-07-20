#!/system/xbin/bash
#
# Copyright (C) 2016-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#

set -e -o pipefail
shopt -s extglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
export PATH="${SELF%/*}:$PATH"

WG_CONFIG=""
INTERFACE=""
NETID=0
ADDRESSES=( )
MTU=""
DNS=""
CONFIG_FILE=""
PROGRAM="${0##*/}"
ARGS=( "$@" )

parse_options() {
	local interface_section=0 line key value
	CONFIG_FILE="$1"
	[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,16}$ ]] && CONFIG_FILE="/data/misc/wireguard/$CONFIG_FILE.conf"
	[[ -e $CONFIG_FILE ]] || die "\`$CONFIG_FILE' does not exist"
	[[ $CONFIG_FILE =~ /?([a-zA-Z0-9_=+.-]{1,16})\.conf$ ]] || die "The config file must be a valid interface name, followed by .conf"
	((($(stat -c '%#a' "$CONFIG_FILE") & 0007) == 0)) || echo "Warning: \`$CONFIG_FILE' is world accessible" >&2
	INTERFACE="${BASH_REMATCH[1]}"
	shopt -s nocasematch
	while read -r line || [[ -n $line ]]; do
		key="${line%%=*}"; key="${key##*( )}"; key="${key%%*( )}"
		value="${line#*=}"; value="${value##*( )}"; value="${value%%*( )}"
		[[ $key == "["* ]] && interface_section=0
		[[ $key == "[Interface]" ]] && interface_section=1
		if [[ $interface_section -eq 1 ]]; then
			case "$key" in
			Address) ADDRESSES+=( ${value//,/ } ); continue ;;
			MTU) MTU="$value"; continue ;;
			DNS) DNS="$value"; continue ;;
			esac
		fi
		WG_CONFIG+="$line"$'\n'
	done < "$CONFIG_FILE"
	shopt -u nocasematch
}

cmd() {
	echo "[#] $*" >&2
	"$@"
}

cndc() {
	local out="$(cmd ndc "$@")"
	[[ $out == *200\ 0* ]] || { echo "$out"; return 1; }
}

die() {
	echo "$PROGRAM: $*" >&2
	exit 1
}

auto_su() {
	[[ $UID == 0 ]] || exec su -p -c "'$SELF' ${ARGS[*]}"
}

add_if() {
	cmd ip link add "$INTERFACE" type wireguard
}

del_if() {
	cmd ip link del "$INTERFACE"
	[[ $(ip rule show) =~ 0xc([0-9a-f]+)/0xcffff\ lookup\ $INTERFACE ]] && cndc network destroy $(( 0x${BASH_REMATCH[1]} ));
}

up_if() {
	while [[ $NETID -lt 4096 ]]; do
		NETID="$RANDOM"
	done
	cmd wg set "$INTERFACE" fwmark 0x20000
	cndc interface setcfg "$INTERFACE" up
	cndc network create "$NETID" vpn 1 1
	cndc network interface add "$NETID" "$INTERFACE"
	cndc network users add "$NETID" 0-99999
}

set_dns() {
	cndc resolver setnetdns "$NETID" "" "$1"
}

add_addr() {
	if [[ $1 == *:* ]]; then
		cndc interface ipv6 "$INTERFACE" enable
		cmd ip -6 addr add "$1" dev "$INTERFACE"
	else
		local ip="${1%%/*}" mask=32
		[[ $1 == */* ]] && mask="${1##*/}"
		cndc interface setcfg "$INTERFACE" "$ip" "$mask"
	fi
}

set_mtu() {
	local mtu=0 endpoint output
	if [[ -n $MTU ]]; then
		cndc interface setmtu "$INTERFACE" "$MTU"
		return
	fi
	while read -r _ endpoint; do
		[[ $endpoint =~ ^\[?([a-z0-9:.]+)\]?:[0-9]+$ ]] || continue
		output="$(ip route get "${BASH_REMATCH[1]}" || true)"
		[[ ( $output =~ mtu\ ([0-9]+) || ( $output =~ dev\ ([^ ]+) && $(ip link show dev "${BASH_REMATCH[1]}") =~ mtu\ ([0-9]+) ) ) && ${BASH_REMATCH[1]} -gt $mtu ]] && mtu="${BASH_REMATCH[1]}"
	done < <(wg show "$INTERFACE" endpoints)
	if [[ $mtu -eq 0 ]]; then
		read -r output < <(ip route show default || true) || true
		[[ ( $output =~ mtu\ ([0-9]+) || ( $output =~ dev\ ([^ ]+) && $(ip link show dev "${BASH_REMATCH[1]}") =~ mtu\ ([0-9]+) ) ) && ${BASH_REMATCH[1]} -gt $mtu ]] && mtu="${BASH_REMATCH[1]}"
	fi
	[[ $mtu -gt 0 ]] || mtu=1500
	cndc interface setmtu "$INTERFACE" $(( mtu - 80 ))
}

add_route() {
	cndc network route add "$NETID" "$INTERFACE" "$1"
}

set_config() {
	cmd wg setconf "$INTERFACE" <(echo "$WG_CONFIG")
}

cmd_usage() {
	cat >&2 <<-_EOF
	Usage: $PROGRAM [ up | down ] [ CONFIG_FILE | INTERFACE ]

	  CONFIG_FILE is a configuration file, whose filename is the interface name
	  followed by \`.conf'. Otherwise, INTERFACE is an interface name, with
	  configuration found at /data/misc/wireguard/INTERFACE.conf. It is to be readable
	  by wg(8)'s \`setconf' sub-command, with the exception of the following additions
	  to the [Interface] section, which are handled by $PROGRAM:

	  - Address: may be specified one or more times and contains one or more
	    IP addresses (with an optional CIDR mask) to be set for the interface.
	  - MTU: an optional MTU for the interface; if unspecified, auto-calculated.
	  - DNS: an optional DNS server to use while the device is up.

	See wg-quick(8) for more info and examples.
	_EOF
}

cmd_up() {
	local i
	[[ -z $(ip link show dev "$INTERFACE" 2>/dev/null) ]] || die "\`$INTERFACE' already exists"
	trap 'del_if; exit' INT TERM EXIT
	add_if
	set_config
	set_mtu
	for i in "${ADDRESSES[@]}"; do
		add_addr "$i"
	done
	up_if
	[[ -z $DNS ]] || set_dns "$DNS"
	for i in $(while read -r _ i; do for i in $i; do [[ $i =~ ^[0-9a-z:.]+/[0-9]+$ ]] && echo "$i"; done; done < <(wg show "$INTERFACE" allowed-ips) | sort -nr -k 2 -t /); do
		[[ $(ip route get "$i" 2>/dev/null) == *dev\ $INTERFACE\ * ]] || add_route "$i"
	done
	trap - INT TERM EXIT
}

cmd_down() {
	[[ -n $(ip link show dev "$INTERFACE" type wireguard 2>/dev/null) ]] || die "\`$INTERFACE' is not a WireGuard interface"
	del_if
}

if [[ $# -eq 1 && ( $1 == --help || $1 == -h || $1 == help ) ]]; then
	cmd_usage
elif [[ $# -eq 2 && $1 == up ]]; then
	auto_su
	parse_options "$2"
	cmd_up
elif [[ $# -eq 2 && $1 == down ]]; then
	auto_su
	parse_options "$2"
	cmd_down
else
	cmd_usage
	exit 1
fi

exit 0
