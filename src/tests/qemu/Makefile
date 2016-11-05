PWD := $(shell pwd)

# Set these from the environment to override
KERNEL_VERSION ?= 4.8.6
BUILD_PATH ?= $(PWD)/../../../qemu-build
DISTFILES_PATH ?= $(PWD)/distfiles
DEBUG_KERNEL ?= no
NR_CPUS ?= 2


DOWNLOAD := wget -O
# DOWNLOAD := curl -f -o

MIRROR := https://download.wireguard.io/qemu-test/distfiles/

CHOST := x86_64-pc-linux-gnu
WIREGUARD_SOURCES := $(wildcard ../../*.c ../../*.h ../../selftest/*.h ../../crypto/*.c ../../crypto/*.h ../../crypto/*.S)
TOOLS_SOURCES := $(wildcard ../../tools/*.c ../../tools*.h ../../uapi.h)

default: qemu

# variable name, tarball project name, version, tarball extension, default URI base
define tar_download =
$(1)_VERSION := $(3)
$(1)_NAME := $(2)-$$($(1)_VERSION)
$(1)_TAR := $(DISTFILES_PATH)/$$($(1)_NAME)$(4)
$(1)_PATH := $(BUILD_PATH)/$$($(1)_NAME)
$(call file_download,$$($(1)_NAME)$(4),$(5))
endef

define file_download =
$(DISTFILES_PATH)/$(1):
	mkdir -p $(DISTFILES_PATH)
	flock -x $$@.lock -c '[ -f $$@ ] && exit 0; $(DOWNLOAD) $$@ $(MIRROR)$(1) || $(DOWNLOAD) $$@ $(2)$(1)'
endef

ifeq ($(findstring -rc,$(KERNEL_VERSION)),)
KERNEL_URL_DIRECTORY := https://www.kernel.org/pub/linux/kernel/v4.x/
else
KERNEL_URL_DIRECTORY := https://www.kernel.org/pub/linux/kernel/v4.x/testing/
endif

$(eval $(call tar_download,KERNEL,linux,$(KERNEL_VERSION),.tar.xz,$(KERNEL_URL_DIRECTORY)))
KERNEL_BZIMAGE := $(KERNEL_PATH)/arch/x86/boot/bzImage
$(eval $(call tar_download,MUSL,musl,1.1.15,.tar.gz,https://www.musl-libc.org/releases/))
$(eval $(call tar_download,LIBMNL,libmnl,1.0.4,.tar.bz2,http://ftp.netfilter.org/pub/libmnl/))
$(eval $(call tar_download,IPERF,iperf,3.1.3,.tar.gz,http://downloads.es.net/pub/iperf/))
$(eval $(call tar_download,BASH,bash,30a978b7d808c067219c95be88c4979b6a7aa251,.tar.gz,http://git.savannah.gnu.org/cgit/bash.git/snapshot/))
$(eval $(call tar_download,IPROUTE2,iproute2,4.3.0,.tar.gz,http://www.kernel.org/pub/linux/utils/net/iproute2/))
$(eval $(call tar_download,IPTABLES,iptables,1.6.0,.tar.bz2,http://ftp.netfilter.org/pub/iptables/))
$(eval $(call tar_download,NMAP,nmap,7.25BETA1,.tar.bz2,http://nmap.org/dist/))

IPUTILS_VERSION := s20160308
IPUTILS_TAR := $(DISTFILES_PATH)/$(IPUTILS_VERSION).tar.gz
IPUTILS_PATH := $(BUILD_PATH)/iputils-$(IPUTILS_VERSION)
$(eval $(call file_download,$(IPUTILS_VERSION).tar.gz,https://github.com/iputils/iputils/archive/))

CFLAGS ?= -O3 -march=native -pipe
CPPFLAGS := -I$(BUILD_PATH)/include

MUSL_CC := $(BUILD_PATH)/musl-gcc

qemu: $(KERNEL_BZIMAGE)
	rm -f $(BUILD_PATH)/result
	qemu-system-x86_64 \
		-nodefaults \
		-nographic \
		-machine q35,accel=kvm \
		-cpu host \
		-smp $(NR_CPUS) \
		-m 64M \
		-object rng-random,id=rng0,filename=/dev/urandom \
		-device virtio-rng-pci,rng=rng0 \
		-device virtio-serial,max_ports=2 \
		-chardev stdio,id=stdio \
		-device virtconsole,chardev=stdio \
		-chardev file,id=status,path=$(BUILD_PATH)/result \
		-device virtserialport,chardev=status \
		-monitor none \
		-kernel $< \
		-append "console=hvc0"
	grep -Fq success $(BUILD_PATH)/result

$(BUILD_PATH)/init-cpio-spec.txt:
	mkdir -p $(BUILD_PATH)
	echo "file /init $(BUILD_PATH)/init 755 0 0" > $@
	echo "file /init.sh $(PWD)/../netns.sh 755 0 0" >> $@
	echo "dir /dev 755 0 0" >> $@
	echo "nod /dev/console 644 0 0 c 5 1" >> $@
	echo "dir /bin 755 0 0" >> $@
	echo "file /bin/iperf3 $(IPERF_PATH)/src/iperf3 755 0 0" >> $@
	echo "file /bin/wg $(BUILD_PATH)/tools/wg 755 0 0" >> $@
	echo "file /bin/bash $(BASH_PATH)/bash 755 0 0" >> $@
	echo "file /bin/ip $(IPROUTE2_PATH)/ip/ip 755 0 0" >> $@
	echo "file /bin/ss $(IPROUTE2_PATH)/misc/ss 755 0 0" >> $@
	echo "file /bin/ping $(IPUTILS_PATH)/ping 755 0 0" >> $@
	echo "file /bin/ncat $(NMAP_PATH)/ncat/ncat 755 0 0" >> $@
	echo "file /bin/xtables-multi $(IPTABLES_PATH)/iptables/xtables-multi 755 0 0" >> $@
	echo "slink /bin/iptables xtables-multi 777 0 0" >> $@
	echo "slink /bin/ping6 ping 777 0 0" >> $@
	echo "dir /lib 755 0 0" >> $@
	echo "file /lib/libc.so $(MUSL_PATH)/lib/libc.so 755 0 0" >> $@
	echo "slink /lib/ld-linux.so.1 libc.so 777 0 0" >> $@

$(KERNEL_PATH)/.installed: $(KERNEL_TAR)
	mkdir -p $(BUILD_PATH)
	tar -C $(BUILD_PATH) -xf $<
	sed -i "/^if INET\$$/a source \"net/wireguard/Kconfig\"" $(KERNEL_PATH)/net/Kconfig
	sed -i "/^obj-\$$(CONFIG_NET).*:=/a obj-\$$(CONFIG_WIREGUARD) += wireguard/" $(KERNEL_PATH)/net/Makefile
	ln -sf $(shell readlink -f ../..) $(KERNEL_PATH)/net/wireguard
	touch $@

$(KERNEL_PATH)/.config: kernel.config | $(KERNEL_PATH)/.installed
	cp kernel.config $(KERNEL_PATH)/minimal.config
	printf 'CONFIG_NR_CPUS=$(NR_CPUS)\nCONFIG_INITRAMFS_SOURCE="$(BUILD_PATH)/init-cpio-spec.txt"\n' >> $(KERNEL_PATH)/minimal.config
	$(MAKE) -C $(KERNEL_PATH) ARCH=x86_64 tinyconfig
	cd $(KERNEL_PATH) && scripts/kconfig/merge_config.sh -n .config minimal.config
	-[ "$(DEBUG_KERNEL)" = "yes" ] && ( cd $(KERNEL_PATH) && scripts/kconfig/merge_config.sh -n .config $(PWD)/debug.config )

$(KERNEL_BZIMAGE): $(KERNEL_PATH)/.installed $(KERNEL_PATH)/.config $(BUILD_PATH)/init-cpio-spec.txt $(MUSL_PATH)/lib/libc.so $(IPERF_PATH)/src/iperf3 $(BUILD_PATH)/tools/wg $(IPUTILS_PATH)/ping $(BASH_PATH)/bash $(IPROUTE2_PATH)/ip/ip $(IPTABLES_PATH)/iptables/xtables-multi $(NMAP_PATH)/ncat/ncat $(BUILD_PATH)/init ../netns.sh $(WIREGUARD_SOURCES) $(TOOLS_SOURCES)
	LOCALVERSION="" $(MAKE) -C $(KERNEL_PATH)

$(BUILD_PATH)/include/linux/.installed: | $(KERNEL_PATH)/.installed
	LOCALVERSION="" $(MAKE) -C $(KERNEL_PATH) INSTALL_HDR_PATH=$(BUILD_PATH) headers_install
	touch $@

$(MUSL_PATH)/lib/libc.so: $(MUSL_TAR) | $(BUILD_PATH)/include/linux/.installed
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	cd $(MUSL_PATH) && ./configure --prefix=/ --disable-static CFLAGS="$(CFLAGS)"
	$(MAKE) -C $(MUSL_PATH)
	strip -s $@

$(MUSL_CC): $(MUSL_PATH)/lib/libc.so
	$(MAKE) -C $(MUSL_PATH) DESTDIR=$(BUILD_PATH) install-headers
	sh $(MUSL_PATH)/tools/musl-gcc.specs.sh $(BUILD_PATH)/include $(MUSL_PATH)/lib /lib/ld-linux.so.1 > $(BUILD_PATH)/musl-gcc.specs
	printf '#!/bin/sh\nexec "$(CC)" "$$@" -specs "$(BUILD_PATH)/musl-gcc.specs"\n' > $(BUILD_PATH)/musl-gcc
	chmod +x $(BUILD_PATH)/musl-gcc

$(IPERF_PATH)/.installed: $(IPERF_TAR)
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	sed -i '1s/^/#include <stdint.h>/' $(IPERF_PATH)/src/cjson.h $(IPERF_PATH)/src/timer.h
	sed -i -r 's/-p?g//g' $(IPERF_PATH)/src/Makefile*
	touch $@

$(IPERF_PATH)/src/iperf3: $(IPERF_PATH)/.installed $(MUSL_CC)
	cd $(IPERF_PATH) && CC="$(MUSL_CC)" CFLAGS="$(CFLAGS) -D_GNU_SOURCE" ./configure --prefix=/ --host=$(CHOST) --enable-static --disable-shared
	$(MAKE) -C $(IPERF_PATH)
	strip -s $@

$(LIBMNL_PATH)/.installed: $(LIBMNL_TAR)
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	touch $@

$(LIBMNL_PATH)/src/.libs/libmnl.a: $(LIBMNL_PATH)/.installed $(MUSL_CC)
	cd $(LIBMNL_PATH) && CC="$(MUSL_CC)" CFLAGS="$(CFLAGS)" ./configure --prefix=/ --host=$(CHOST) --enable-static --disable-shared
	$(MAKE) -C $(LIBMNL_PATH)

$(BUILD_PATH)/tools/wg: $(MUSL_CC) $(TOOLS_SOURCES) $(LIBMNL_PATH)/src/.libs/libmnl.a | $(BUILD_PATH)/include/linux/.installed
	cp -pr ../../uapi.h ../../tools $(BUILD_PATH)/
	$(MAKE) -C $(BUILD_PATH)/tools clean
	CC="$(MUSL_CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS) -L$(LIBMNL_PATH)/src/.libs" $(MAKE) -C $(BUILD_PATH)/tools LIBMNL_CFLAGS="-I$(LIBMNL_PATH)/include" LIBMNL_LDLIBS="-lmnl" wg
	strip -s $@

$(BUILD_PATH)/init: init.c $(MUSL_CC)
	$(MUSL_CC) -o $@ -O3 -std=gnu11 $<
	strip -s $@

$(IPUTILS_PATH)/.installed: $(IPUTILS_TAR)
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	touch $@

$(IPUTILS_PATH)/ping: $(IPUTILS_PATH)/.installed $(MUSL_CC) | $(BUILD_PATH)/include/linux/.installed
	$(MAKE) -C $(IPUTILS_PATH) CC="$(MUSL_CC)" USE_CAP=no USE_IDN=no USE_NETTLE=no USE_CRYPTO=no ping
	strip -s $@

$(BASH_PATH)/.installed: $(BASH_TAR)
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	touch $@

$(BASH_PATH)/bash: $(BASH_PATH)/.installed $(MUSL_CC) | $(BUILD_PATH)/include/linux/.installed
	cd $(BASH_PATH) && CC="$(MUSL_CC)" CFLAGS="$(CFLAGS)" ./configure --prefix=/ --host=$(CHOST) --without-bash-malloc --disable-debugger --disable-help-builtin --disable-history --disable-multibyte --disable-progcomp --disable-readline --disable-mem-scramble
	$(MAKE) -C $(BASH_PATH)
	strip -s $@

$(IPROUTE2_PATH)/.installed: $(IPROUTE2_TAR)
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	sed -i '/ARPD/d' $(IPROUTE2_PATH)/Makefile
	sed -i 's/arpd.8//' $(IPROUTE2_PATH)/man/man8/Makefile
	sed -i 's/m_ipt.o//;s/[^ ]*_bpf.o//' $(IPROUTE2_PATH)/tc/Makefile
	sed -i '/#include <linux\/in\.h>/d;/#include <linux\/in6\.h>/d' $(IPROUTE2_PATH)/include/libiptc/ipt_kernel_headers.h $(IPROUTE2_PATH)/include/linux/if_bridge.h $(IPROUTE2_PATH)/include/linux/netfilter.h $(IPROUTE2_PATH)/include/linux/xfrm.h
	printf 'TC_CONFIG_XT=n\nTC_CONFIG_ATM=n\nTC_CONFIG_IPSET=n\nIP_CONFIG_SETNS=y\n' > $(IPROUTE2_PATH)/Config
	touch $@

$(IPROUTE2_PATH)/ip/ip: $(IPROUTE2_PATH)/.installed $(MUSL_CC) | $(BUILD_PATH)/include/linux/.installed
	CFLAGS="$(CFLAGS)" $(MAKE) -C $(IPROUTE2_PATH) PREFIX=/ CC="$(MUSL_CC)"
	strip -s $(IPROUTE2_PATH)/ip/ip $(IPROUTE2_PATH)/misc/ss

$(IPTABLES_PATH)/.installed: $(IPTABLES_TAR)
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	rm -f $(IPTABLES_PATH)/include/linux/{kernel,types}.h
	sed -i -e "/nfnetlink=[01]/s:=[01]:=0:" -e "/nfconntrack=[01]/s:=[01]:=0:" $(IPTABLES_PATH)/configure
	touch $@

$(IPTABLES_PATH)/iptables/xtables-multi: $(IPTABLES_PATH)/.installed $(MUSL_CC) $(LIBMNL_PATH)/src/.libs/libmnl.a | $(KERNEL_PATH)/.installed
	cd $(IPTABLES_PATH) && PKG_CONFIG_LIBDIR="$(LIBMNL_PATH)" CC="$(MUSL_CC)" CFLAGS="$(CFLAGS)" ./configure --prefix=/ --host=$(CHOST) --enable-static --disable-shared --disable-nftables --disable-bpf-compiler --disable-nfsynproxy --disable-libipq --with-kernel=$(KERNEL_PATH)
	$(MAKE) -C $(IPTABLES_PATH)
	strip -s $@

$(NMAP_PATH)/.installed: $(NMAP_TAR)
	flock -x $<.lock true
	tar -C $(BUILD_PATH) -xf $<
	touch $@

$(NMAP_PATH)/ncat/ncat: $(NMAP_PATH)/.installed $(MUSL_CC) | $(KERNEL_PATH)/.installed
	cd $(NMAP_PATH) && CC="$(MUSL_CC)" CFLAGS="$(CFLAGS)" ./configure --prefix=/ --host=$(CHOST) --enable-static --disable-shared --without-ndiff --without-zenmap --without-nping --with-libpcap=included --with-libpcre=included --with-libdnet=included --without-liblua --with-liblinear=included --without-nmap-update --without-openssl --with-pcap=linux
	$(MAKE) -C $(NMAP_PATH) build-ncat
	strip -s $@

clean:
	rm -rf $(BUILD_PATH)

distclean: clean
	rm -rf $(DISTFILES_PATH)
