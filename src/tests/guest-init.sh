#!/bin/bash
export PATH="/tools:/sbin:/bin"
/bin/busybox ln -sf / /usr
/bin/busybox --install -s
mkdir /run /proc /tmp /sys /var /dev
ln -s /run /var/run
mount -t tmpfs none /run
mount -t tmpfs none /tmp
mount -t sysfs none /sys
mount -t proc none /proc
mount -t devtmpfs none /dev
ln -s /proc/self/fd /dev/fd
/wireguard/tests/netns.sh --no-module-insert && touch /wg-netns-success
echo o > /proc/sysrq-trigger
sleep 10000000000
