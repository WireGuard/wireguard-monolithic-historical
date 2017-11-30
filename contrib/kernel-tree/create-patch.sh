#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

WG="$(readlink -f "$(dirname "$(readlink -f "$0")")/../../src/")"

for i in "$WG"/*.c "$WG"/*.h "$WG"/uapi/*.h "$WG"/selftest/*.h "$WG"/crypto/*.c "$WG"/crypto/*.h "$WG"/crypto/*.S "$WG"/Kbuild "$WG"/Kconfig $(find "$WG"/compat -name '*.c' -o -name '*.h' -o -name '*.include'); do
	diff -u /dev/null "$i" | sed "s:${WG}:b/net/wireguard:;s:Kbuild:Makefile:"
done

cat <<_EOF
--- a/net/Kconfig
+++ b/net/Kconfig
@@ -85,2 +85,3 @@ config INET
 if INET
+source "net/wireguard/Kconfig"
 source "net/ipv4/Kconfig"
--- a/net/Makefile
+++ b/net/Makefile
@@ -16,2 +16,3 @@
 obj-\$(CONFIG_NETFILTER)		+= netfilter/
+obj-\$(CONFIG_WIREGUARD)		+= wireguard/
 obj-\$(CONFIG_INET)		+= ipv4/
_EOF
