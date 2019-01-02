#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#

set -e -o pipefail
shopt -s extglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
export PATH="${SELF%/*}:$PATH"

WG_CONFIG=""
INTERFACE=""
ADDRESSES=( )
MTU=""
DNS=( )
TABLE=""
PRE_UP=( )
POST_UP=( )
PRE_DOWN=( )
POST_DOWN=( )
SAVE_CONFIG=0
CONFIG_FILE=""
PROGRAM="${0##*/}"
ARGS=( "$@" )

cmd() {
	echo "[#] $*" >&2
	"$@"
}

die() {
	echo "$PROGRAM: $*" >&2
	exit 1
}

parse_options() {
	local interface_section=0 line key value stripped
	CONFIG_FILE="$1"
	[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] && CONFIG_FILE="/etc/wireguard/$CONFIG_FILE.conf"
	[[ -e $CONFIG_FILE ]] || die "\`$CONFIG_FILE' does not exist"
	[[ $CONFIG_FILE =~ (^|/)([a-zA-Z0-9_=+.-]{1,15})\.conf$ ]] || die "The config file must be a valid interface name, followed by .conf"
	CONFIG_FILE="$(readlink -f "$CONFIG_FILE")"
	((($(stat -c '0%#a' "$CONFIG_FILE") & $(stat -c '0%#a' "${CONFIG_FILE%/*}") & 0007) == 0)) || echo "Warning: \`$CONFIG_FILE' is world accessible" >&2
	INTERFACE="${BASH_REMATCH[2]}"
	shopt -s nocasematch
	while read -r line || [[ -n $line ]]; do
		stripped="${line%%\#*}"
		key="${stripped%%=*}"; key="${key##*([[:space:]])}"; key="${key%%*([[:space:]])}"
		value="${stripped#*=}"; value="${value##*([[:space:]])}"; value="${value%%*([[:space:]])}"
		[[ $key == "["* ]] && interface_section=0
		[[ $key == "[Interface]" ]] && interface_section=1
		if [[ $interface_section -eq 1 ]]; then
			case "$key" in
			Address) ADDRESSES+=( ${value//,/ } ); continue ;;
			MTU) MTU="$value"; continue ;;
			DNS) DNS+=( ${value//,/ } ); continue ;;
			Table) TABLE="$value"; continue ;;
			PreUp) PRE_UP+=( "$value" ); continue ;;
			PreDown) PRE_DOWN+=( "$value" ); continue ;;
			PostUp) POST_UP+=( "$value" ); continue ;;
			PostDown) POST_DOWN+=( "$value" ); continue ;;
			SaveConfig) read_bool SAVE_CONFIG "$value"; continue ;;
			esac
		fi
		WG_CONFIG+="$line"$'\n'
	done < "$CONFIG_FILE"
	shopt -u nocasematch
}

read_bool() {
	case "$2" in
	true) printf -v "$1" 1 ;;
	false) printf -v "$1" 0 ;;
	*) die "\`$2' is neither true nor false"
	esac
}

auto_su() {
	[[ $UID == 0 ]] || exec sudo -p "$PROGRAM must be run as root. Please enter the password for %u to continue: " -- "$BASH" -- "$SELF" "${ARGS[@]}"
}

add_if() {
	local ret
	if ! cmd ip link add "$INTERFACE" type wireguard; then
		ret=$?
		[[ -e /sys/module/wireguard ]] || ! command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-wireguard-go}" >/dev/null && exit $ret
		echo "[!] Missing WireGuard kernel module. Falling back to slow userspace implementation."
		cmd "${WG_QUICK_USERSPACE_IMPLEMENTATION:-wireguard-go}" "$INTERFACE"
	fi
}

del_if() {
	local table
	[[ $HAVE_SET_DNS -eq 0 ]] || unset_dns
	if [[ -z $TABLE || $TABLE == auto ]] && get_fwmark table && [[ $(wg show "$INTERFACE" allowed-ips) =~ /0(\ |$'\n'|$) ]]; then
		while [[ $(ip -4 rule show) == *"lookup $table"* ]]; do
			cmd ip -4 rule delete table $table
		done
		while [[ $(ip -4 rule show) == *"from all lookup main suppress_prefixlength 0"* ]]; do
			cmd ip -4 rule delete table main suppress_prefixlength 0
		done
		while [[ $(ip -6 rule show) == *"lookup $table"* ]]; do
			cmd ip -6 rule delete table $table
		done
		while [[ $(ip -6 rule show) == *"from all lookup main suppress_prefixlength 0"* ]]; do
			cmd ip -6 rule delete table main suppress_prefixlength 0
		done
	fi
	cmd ip link delete dev "$INTERFACE"
}

add_addr() {
	cmd ip address add "$1" dev "$INTERFACE"
}

set_mtu_up() {
	local mtu=0 endpoint output
	if [[ -n $MTU ]]; then
		cmd ip link set mtu "$MTU" up dev "$INTERFACE"
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
	cmd ip link set mtu $(( mtu - 80 )) up dev "$INTERFACE"
}

resolvconf_iface_prefix() {
	[[ -f /etc/resolvconf/interface-order ]] || return 0
	local iface
	while read -r iface; do
		[[ $iface =~ ^([A-Za-z0-9-]+)\*$ ]] || continue
		echo "${BASH_REMATCH[1]}." && return 0
	done < /etc/resolvconf/interface-order
}

HAVE_SET_DNS=0
set_dns() {
	[[ ${#DNS[@]} -gt 0 ]] || return 0
	printf 'nameserver %s\n' "${DNS[@]}" | cmd resolvconf -a "$(resolvconf_iface_prefix)$INTERFACE" -m 0 -x
	HAVE_SET_DNS=1
}

unset_dns() {
	[[ ${#DNS[@]} -gt 0 ]] || return 0
	cmd resolvconf -d "$(resolvconf_iface_prefix)$INTERFACE"
}

add_route() {
	[[ $TABLE != off ]] || return 0

	if [[ -n $TABLE && $TABLE != auto ]]; then
		cmd ip route add "$1" dev "$INTERFACE" table "$TABLE"
	elif [[ $1 == */0 ]]; then
		add_default "$1"
	else
		[[ $(ip route get "$1" 2>/dev/null) == *dev\ $INTERFACE\ * ]] || cmd ip route add "$1" dev "$INTERFACE"
	fi
}

get_fwmark() {
	local fwmark
	fwmark="$(wg show "$INTERFACE" fwmark)" || return 1
	[[ -n $fwmark && $fwmark != off ]] || return 1
	printf -v "$1" "%d" "$fwmark"
	return 0
}

add_default() {
	local table proto key value
	if ! get_fwmark table; then
		table=51820
		while [[ -n $(ip -4 route show table $table) || -n $(ip -6 route show table $table) ]]; do
			((table++))
		done
		cmd wg set "$INTERFACE" fwmark $table
	fi
	proto=-4
	[[ $1 == *:* ]] && proto=-6
	cmd ip $proto route add "$1" dev "$INTERFACE" table $table
	cmd ip $proto rule add not fwmark $table table $table
	cmd ip $proto rule add table main suppress_prefixlength 0
	while read -r key _ value; do
		[[ $value -eq 1 ]] && sysctl -q "$key=2"
	done < <(sysctl -a -r '^net\.ipv4.conf\.[^ .=]+\.rp_filter$')
	return 0
}

set_config() {
	cmd wg setconf "$INTERFACE" <(echo "$WG_CONFIG")
}

save_config() {
	local old_umask new_config current_config address cmd
	[[ $(ip -all -brief address show dev "$INTERFACE") =~ ^$INTERFACE\ +\ [A-Z]+\ +(.+)$ ]] || true
	new_config=$'[Interface]\n'
	for address in ${BASH_REMATCH[1]}; do
		new_config+="Address = $address"$'\n'
	done
	while read -r address; do
		[[ $address =~ ^nameserver\ ([a-zA-Z0-9_=+:%.-]+)$ ]] && new_config+="DNS = ${BASH_REMATCH[1]}"$'\n'
	done < <(resolvconf -l "$(resolvconf_iface_prefix)$INTERFACE" 2>/dev/null || cat "/etc/resolvconf/run/interface/$(resolvconf_iface_prefix)$INTERFACE" 2>/dev/null)
	[[ -n $MTU && $(ip link show dev "$INTERFACE") =~ mtu\ ([0-9]+) ]] && new_config+="MTU = ${BASH_REMATCH[1]}"$'\n'
	[[ -n $TABLE ]] && new_config+="Table = $TABLE"$'\n'
	[[ $SAVE_CONFIG -eq 0 ]] || new_config+=$'SaveConfig = true\n'
	for cmd in "${PRE_UP[@]}"; do
		new_config+="PreUp = $cmd"$'\n'
	done
	for cmd in "${POST_UP[@]}"; do
		new_config+="PostUp = $cmd"$'\n'
	done
	for cmd in "${PRE_DOWN[@]}"; do
		new_config+="PreDown = $cmd"$'\n'
	done
	for cmd in "${POST_DOWN[@]}"; do
		new_config+="PostDown = $cmd"$'\n'
	done
	old_umask="$(umask)"
	umask 077
	current_config="$(cmd wg showconf "$INTERFACE")"
	trap 'rm -f "$CONFIG_FILE.tmp"; exit' INT TERM EXIT
	echo "${current_config/\[Interface\]$'\n'/$new_config}" > "$CONFIG_FILE.tmp" || die "Could not write configuration file"
	sync "$CONFIG_FILE.tmp"
	mv "$CONFIG_FILE.tmp" "$CONFIG_FILE" || die "Could not move configuration file"
	trap - INT TERM EXIT
	umask "$old_umask"
}

execute_hooks() {
	local hook
	for hook in "$@"; do
		hook="${hook//%i/$INTERFACE}"
		echo "[#] $hook" >&2
		(eval "$hook")
	done
}

cmd_usage() {
	cat >&2 <<-_EOF
	Usage: $PROGRAM [ up | down | save ] [ CONFIG_FILE | INTERFACE ]

	  CONFIG_FILE is a configuration file, whose filename is the interface name
	  followed by \`.conf'. Otherwise, INTERFACE is an interface name, with
	  configuration found at /etc/wireguard/INTERFACE.conf. It is to be readable
	  by wg(8)'s \`setconf' sub-command, with the exception of the following additions
	  to the [Interface] section, which are handled by $PROGRAM:

	  - Address: may be specified one or more times and contains one or more
	    IP addresses (with an optional CIDR mask) to be set for the interface.
	  - DNS: an optional DNS server to use while the device is up.
	  - MTU: an optional MTU for the interface; if unspecified, auto-calculated.
	  - Table: an optional routing table to which routes will be added; if
	    unspecified or \`auto', the default table is used. If \`off', no routes
	    are added.
	  - PreUp, PostUp, PreDown, PostDown: script snippets which will be executed
	    by bash(1) at the corresponding phases of the link, most commonly used
	    to configure DNS. The string \`%i' is expanded to INTERFACE.
	  - SaveConfig: if set to \`true', the configuration is saved from the current
	    state of the interface upon shutdown.

	See wg-quick(8) for more info and examples.
	_EOF
}

cmd_up() {
	local i
	[[ -z $(ip link show dev "$INTERFACE" 2>/dev/null) ]] || die "\`$INTERFACE' already exists"
	trap 'del_if; exit' INT TERM EXIT
	execute_hooks "${PRE_UP[@]}"
	add_if
	set_config
	for i in "${ADDRESSES[@]}"; do
		add_addr "$i"
	done
	set_mtu_up
	set_dns
	for i in $(while read -r _ i; do for i in $i; do [[ $i =~ ^[0-9a-z:.]+/[0-9]+$ ]] && echo "$i"; done; done < <(wg show "$INTERFACE" allowed-ips) | sort -nr -k 2 -t /); do
		add_route "$i"
	done
	execute_hooks "${POST_UP[@]}"
	trap - INT TERM EXIT
}

cmd_down() {
	[[ " $(wg show interfaces) " == *" $INTERFACE "* ]] || die "\`$INTERFACE' is not a WireGuard interface"
	execute_hooks "${PRE_DOWN[@]}"
	[[ $SAVE_CONFIG -eq 0 ]] || save_config
	del_if
	unset_dns
	execute_hooks "${POST_DOWN[@]}"
}

cmd_save() {
	[[ " $(wg show interfaces) " == *" $INTERFACE "* ]] || die "\`$INTERFACE' is not a WireGuard interface"
	save_config
}

# ~~ function override insertion point ~~

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
elif [[ $# -eq 2 && $1 == save ]]; then
	auto_su
	parse_options "$2"
	cmd_save
else
	cmd_usage
	exit 1
fi

exit 0
