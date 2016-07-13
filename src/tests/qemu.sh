#!/bin/bash
# This compiles a kernel, creates a rootfs, and then starts up
# QEMU to run the netns.sh test.
#
# The exit code is 0 when this is successful.

set -ex
cleanup() {
	set +e
	[[ -d $scratch_dir ]] || exit
	cd /
	rm -rf "$scratch_dir"
}
trap cleanup EXIT
wireguard_dir="$(readlink -f "$(dirname "$(readlink -f "$0")")/..")"
scratch_dir="$(mktemp -d)"
cd "$scratch_dir"
mkdir -p root/tools
root_dir="$(readlink -f root)"
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.6.4.tar.xz
tar xf linux-*.tar.xz
cd linux-*
make x86_64_defconfig
sed -i "/^if NET\$/a source \"$wireguard_dir/Kconfig\"" net/Kconfig
echo "obj-y += ../../../../../../../../../../../../../../../../../../../../../..$wireguard_dir/" >> net/Makefile
cat >> .config <<_EOF
CONFIG_NET=y
CONFIG_INET=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_XTABLES=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_NF_CONNTRACK=y
CONFIG_IP6_NF_IPTABLES=y
CONFIG_IPV6=y
CONFIG_NET_UDP_TUNNEL=y
CONFIG_NETFILTER_XT_MATCH_HASHLIMIT=y
CONFIG_CRYPTO_MANAGER=y
CONFIG_WIREGUARD=y
CONFIG_WIREGUARD_DEBUG=y
CONFIG_WIREGUARD_PARALLEL=y
CONFIG_HW_RANDOM_VIRTIO=y
_EOF
make kvmconfig
make -j$(nproc)
make INSTALL_HDR_PATH="$root_dir" headers_install
cd ..

wget https://www.musl-libc.org/releases/musl-1.1.15.tar.gz
tar xf musl-*.tar.gz
cd musl-*
unset CC
./configure --prefix="$root_dir"
make -j$(nproc)
make install
export CC="$root_dir/bin/musl-gcc"
export CFLAGS="-static -O2"
cd ..
wget http://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz
tar xf bash-*.tar.gz
cd bash-*
for i in {1..43}; do
        wget -O - http://ftp.gnu.org/gnu/bash/bash-4.3-patches/bash43-$(printf '%03d' $i) | patch -p0
done
./configure --prefix="$root_dir" --without-bash-malloc
make -j$(nproc)
make install
cd ..
wget https://busybox.net/downloads/busybox-1.25.0.tar.bz2
tar xf busybox-*.tar.bz2
cd busybox-*
make defconfig
make -j$(nproc)
cp busybox "$root_dir/bin/"
cd ..
wget http://ftp.netfilter.org/pub/libmnl/libmnl-1.0.4.tar.bz2
tar xf libmnl-*.tar.bz2
cd libmnl-*
./configure --prefix="$root_dir" --enable-static --disable-shared
make -j$(nproc)
make install
cd ..
wget https://www.kernel.org/pub/linux/utils/net/iproute2/iproute2-4.3.0.tar.xz
tar xf iproute2-*.tar.xz
cd iproute2-*
sed -i 's/-O2/-O2 -static/' Makefile
sed -i '/ARPD/d' Makefile
sed -i 's/arpd.8//' man/man8/Makefile
sed -i 's/m_ipt.o//' tc/Makefile
sed -i 's/[^ ]*_bpf.o//' tc/Makefile
echo -e "TC_CONFIG_XT=n\nTC_CONFIG_ATM=n\nTC_CONFIG_IPSET=n\nIP_CONFIG_SETNS=y" > Config
wget -O - https://cgit.gentoo.org/proj/musl.git/plain/sys-apps/iproute2/files/iproute2-4.3.0-musl.patch | patch -p1
make -j$(nproc) PREFIX="$root_dir" CC="$CC" LDFLAGS=-static
cp ip/ip misc/ss "$root_dir/tools"
cd ..
wget http://downloads.es.net/pub/iperf/iperf-3.1.3.tar.gz
tar xf iperf-*.tar.gz
cd iperf-*
wget -O - https://github.com/esnet/iperf/commit/1fe02385b60c9dcd8a04b8bd3ff5cff120ec35a6.diff | patch -p1
sed -i 's/-pg//;s/-g//' src/Makefile*
LDFLAGS=-static CFLAGS="-static -O2 -D_GNU_SOURCE" ./configure --prefix="$root_dir" --disable-shared --enable-static
make -j$(nprocs)
rm src/iperf3
sed -i 's/iperf3_CFLAGS =/iperf3_CFLAGS = -all-static/' src/Makefile
make
cp src/iperf3 "$root_dir/tools"
wget https://github.com/iputils/iputils/archive/s20160308.tar.gz -O iputils-s20160308.tar.gz
tar xf iputils-*.tar.gz
cd iputils-*
LDFLAGS=-static make CC="$CC" USE_IDN=no USE_CAP=no USE_CRYPTO=no USE_GCRYPT=no USE_NETTLE=no ping -j$(nproc)
cp ping $root_dir/tools/ping
cp ping $root_dir/tools/ping6
cd ..
cp -r "$wireguard_dir" "$root_dir/wireguard"
cd "$root_dir/wireguard/tools"
make clean
LDFLAGS=-static PKG_CONFIG_SYSROOT_DIR="$root_dir" PKG_CONFIG_PATH="$root_dir/lib/pkgconfig" PKG_CONFIG_LIBDIR="$root_dir/lib/pkgconfig" PREFIX="$root_dir" make -j$(nproc)
cd "$root_dir/.."

qemu-system-x86_64 \
	-enable-kvm \
	-cpu host \
	-smp 2 \
	-m 64M \
	-nographic \
	-object rng-random,id=rng0,filename=/dev/urandom \
	-device virtio-rng-pci,rng=rng0 \
	-kernel linux-*/arch/x86/boot/bzImage \
	-fsdev local,path="$root_dir",security_model=none,id=root \
	-device virtio-9p-pci,fsdev=root,mount_tag=/dev/root \
	-append "root=/dev/root rw rootfstype=9p rootflags=trans=virtio console=ttyS0 init=/wireguard/tests/guest-init.sh"

[[ -e $root_dir/wg-netns-success ]]
