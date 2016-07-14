#!/bin/sh

K="$1"
WG="$(readlink -f "$(dirname "$(readlink -f "$0")")/../src/")"

if [[ ! -e $K/net/Kconfig ]]; then
	echo "You must specify the location of kernel sources as the first argument." >&2
	exit 1
fi

sed -i "/^if INET\$/a source \"$WG/Kconfig\"" "$K/net/Kconfig"
echo "obj-y += ../../../../../../../../../../../../../../../../../../../../../..$WG/" >> "$K/net/Makefile"
