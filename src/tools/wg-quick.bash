#!/bin/bash
#
# Copyright (c) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#

set -e -o pipefail
shopt -s extglob

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
export PATH="${SELF%/*}:$PATH"

WG_CONFIG=""
INTERFACE=""
ADDRESSES=( )
PRE_UP=""
POST_UP=""
PRE_DOWN=""
POST_DOWN=""
SAVE_CONFIG=0
CONFIG_FILE=""
PROGRAM="${0##*/}"
ARGS=( "$@" )

parse_options() {
	local interface_section=0 line key value
	CONFIG_FILE="$1"
	[[ $CONFIG_FILE =~ ^[a-zA-Z0-9_=+.-]{1,16}$ ]] && CONFIG_FILE="/etc/wireguard/$CONFIG_FILE.conf"
	[[ -e $CONFIG_FILE ]] || die "\`$CONFIG_FILE' does not exist"
	[[ $CONFIG_FILE =~ /?([a-zA-Z0-9_=+.-]{1,16})\.conf$ ]] || die "The config file must be a valid interface name, followed by .conf"
	((($(stat -c '%#a' "$CONFIG_FILE") & 0007) == 0)) || echo "Warning: \`$CONFIG_FILE' is world accessible" >&2
	INTERFACE="${BASH_REMATCH[1]}"
	shopt -s nocasematch
	while read -r line; do
		key="${line%%=*}"; key="${key##*( )}"; key="${key%%*( )}"
		value="${line#*=}"; value="${value##*( )}"; value="${value%%*( )}"
		[[ $key == "["* ]] && interface_section=0
		[[ $key == "[Interface]" ]] && interface_section=1
		if [[ $interface_section -eq 1 ]]; then
			case "$key" in
			Address) ADDRESSES+=( ${value//,/ } ); continue ;;
			PreUp) PRE_UP="$value"; continue ;;
			PreDown) PRE_DOWN="$value"; continue ;;
			PostUp) POST_UP="$value"; continue ;;
			PostDown) POST_DOWN="$value"; continue ;;
			SaveConfig) read_bool SAVE_CONFIG "$value"; continue ;;
			esac
		fi
		WG_CONFIG+="$line"$'\n'
	done < "$CONFIG_FILE"
	shopt -u nocasematch
}

read_bool() {
	local -n out="$1"
	case "$2" in
	true) out=1 ;;
	false) out=0 ;;
	*) die "\`$2' is neither true nor false"
	esac
}

cmd() {
	echo "[#] $*" >&2
	"$@"
}

die() {
	echo "$PROGRAM: $*" >&2
	exit 1
}

auto_su() {
	[[ $UID == 0 ]] || exec sudo -p "$PROGRAM must be run as root. Please enter the password for %u to continue: " "$SELF" "${ARGS[@]}"
}

add_if() {
	cmd ip link add "$INTERFACE" type wireguard
}

del_if() {
	if [[ $(ip route show table all) =~ .*\ dev\ $INTERFACE\ table\ ([0-9]+)\ .* ]]; then
		cmd ip rule delete table "${BASH_REMATCH[1]}"
		cmd ip rule delete table main suppress_prefixlength 0 2>/dev/null
	fi
	cmd ip link delete dev "$INTERFACE"
}

up_if() {
	cmd ip link set "$INTERFACE" up
}

add_addr() {
	cmd ip address add "$1" dev "$INTERFACE"
}

add_route() {
	if [[ $1 == 0.0.0.0/0 || $1 == ::/0 ]]; then
		add_default "$1"
	else
		cmd ip route add "$1" dev "$INTERFACE"
	fi
}

add_default() {
	[[ $(join <(wg show "$INTERFACE" allowed-ips) <(wg show "$INTERFACE" endpoints)) =~ .*\ ${1//./\\.}\ ([0-9.:a-f]+):[0-9]+$ ]] && local endpoint="${BASH_REMATCH[1]}"
	[[ -n $endpoint ]] || return 0
	local table=51820
	while [[ -n $(ip route show table $table) ]]; do ((table++)); done
	cmd ip route add "$1" dev "$INTERFACE" table $table
	cmd ip rule add not to "$endpoint" table $table
	cmd ip rule add table main suppress_prefixlength 0
}

set_config() {
	cmd wg setconf "$INTERFACE" <(echo "$WG_CONFIG")
}

save_config() {
	local old_umask new_config current_config address
	[[ $(ip -all -brief address show dev "$INTERFACE") =~ ^$INTERFACE\ +\ [A-Z]+\ +(.+)$ ]] || true
	new_config=$'[Interface]\n'
	for address in ${BASH_REMATCH[1]}; do
		new_config+="Address = $address"$'\n'
	done
	[[ $SAVE_CONFIG -eq 0 ]] || new_config+=$'SaveConfig = true\n'
	[[ -z $PRE_UP ]] || new_config+="PreUp = $PRE_UP"$'\n'
	[[ -z $POST_UP ]] || new_config+="PostUp = $POST_UP"$'\n'
	[[ -z $PRE_DOWN ]] || new_config+="PreDown = $PRE_DOWN"$'\n'
	[[ -z $POST_DOWN ]] || new_config+="PostDown = $POST_DOWN"$'\n'
	old_umask="$(umask)"
	umask 077
	current_config="$(cmd wg showconf "$INTERFACE")"
	trap "rm -f '$CONFIG_FILE.tmp; exit'" INT TERM EXIT
	echo "${current_config/\[Interface\]$'\n'/$new_config}" > "$CONFIG_FILE.tmp" || die "Could not write configuration file"
	mv "$CONFIG_FILE.tmp" "$CONFIG_FILE" || die "Could not move configuration file"
	trap - INT TERM EXIT
	umask "$old_umask"
}

execute_hook() {
	[[ -n $1 ]] || return 0
	local hook="${1//%i/$INTERFACE}"
	echo "[#] $hook" >&2
	(eval "$hook")
}

cmd_usage() {
	cat >&2 <<-_EOF
	Usage: $PROGRAM [ up | down ] [ CONFIG_FILE | INTERFACE ]

	  CONFIG_FILE is a configuration file, whose filename is the interface name
	  followed by \`.conf'. Otherwise, INTERFACE is an interface name, with
	  configuration found at /etc/wireguard/INTERFACE.conf. It is to be readable
	  by wg(8)'s \`setconf' sub-command, with the exception of the following additions
	  to the [Interface] section, which are handled by $PROGRAM:

	  - Address: may be specified one or more times and contains one or more
	    IP addresses (with an optional CIDR mask) to be set for the interface.
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
	execute_hook "$PRE_UP"
	add_if
	set_config
	for i in "${ADDRESSES[@]}"; do
		add_addr "$i"
	done
	up_if
	for i in $(wg show "$INTERFACE" allowed-ips | grep -Po '(?<=[\t ])[0-9.:/a-f]+' | sort -nr -k 2 -t /); do
		[[ $(ip route get "$i" 2>/dev/null) == *dev\ $INTERFACE\ * ]] || add_route "$i"
	done
	execute_hook "$POST_UP"
	trap - INT TERM EXIT
}

cmd_down() {
	[[ -n $(ip link show dev "$INTERFACE" type wireguard 2>/dev/null) ]] || die "\`$INTERFACE' is not a WireGuard interface"
	execute_hook "$PRE_DOWN"
	[[ $SAVE_CONFIG -eq 0 ]] || save_config
	del_if
	execute_hook "$POST_DOWN"
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
