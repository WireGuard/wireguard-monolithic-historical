#!/bin/sh

WG="$(readlink -f "$(dirname "$(readlink -f "$0")")/../../src/")"

for i in "$WG"/*.c "$WG"/*.h "$WG"/selftest/*.h "$WG"/crypto/*.c "$WG"/crypto/*.h "$WG"/crypto/*.S "$WG"/Kbuild "$WG"/Kconfig; do
	diff -u /dev/null "$i" | sed "s:${WG}:b/net/wireguard:;s:Kbuild:Makefile:"
done

cat <<_EOF
--- a/net/Kconfig
+++ b/net/Kconfig
@@ -85,1 +85,2 @@ config INET
 if INET
+source "net/wireguard/Kconfig"
--- a/net/Makefile
+++ b/net/Makefile
@@ -8,1 +8,2 @@
 obj-\$(CONFIG_NET)		:= socket.o core/
+obj-\$(CONFIG_WIREGUARD)		+= wireguard/
_EOF
