#!/bin/sh
mount -o rw,remount /system

cp -v ./addonsd.sh /system/addon.d/40-wireguard.sh
if [ -f ./wg ]; then
	cp -v ./wg /system/xbin/wg
else
	echo "Warning: this directory does not contain wg. You may have forgotten to compile it yourself?" >&2
fi
cp -v ./wg-quick.bash /system/xbin/wg-quick
chmod 755 /system/xbin/wg /system/xbin/wg-quick /system/addon.d/40-wireguard.sh
mkdir -pvm 700 /data/misc/wireguard

mount -o ro,remount /system
