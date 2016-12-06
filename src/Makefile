KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DKMSDIR ?= $(SRCDIR)/wireguard

PWD := $(shell pwd)

all: module tools
debug: module-debug tools

version.h:
	@export GIT_CEILING_DIRECTORIES="$$(readlink -f ../..)" && \
	ver="#define WIREGUARD_VERSION \"$$(git describe --dirty 2>/dev/null)\"" && \
	[ "$$(cat version.h 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.h && \
	git update-index --assume-unchanged version.h || true

dkms.conf:
	@export GIT_CEILING_DIRECTORIES="$$(readlink -f ../..)" && \
	ver="$$(git describe --dirty 2>/dev/null)" && \
	. ./dkms.conf && \
	[ "$$PACKAGE_VERSION" != "$$ver" ] && \
	sed -i "s/PACKAGE_VERSION=.*/PACKAGE_VERSION=\"$$ver\"/" dkms.conf && \
	git update-index --assume-unchanged dkms.conf || true

module: version.h
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

module-debug: version.h
	$(MAKE) -C $(KERNELDIR) M=$(PWD) V=1 CONFIG_WIREGUARD_DEBUG=y modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	$(MAKE) -C tools clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a
	$(MAKE) -C tools install

DKMS_TOP_LEVEL := Makefile Kbuild Kconfig $(filter-out wireguard.mod.c, $(wildcard *.c)) $(filter-out version.h, $(wildcard *.h)) version.h dkms.conf
DKMS_SELFTEST_LEVEL := $(wildcard selftest/*.c) $(wildcard selftest/*.h)
DKMS_CRYPTO_LEVEL := $(wildcard crypto/*.c) $(wildcard crypto/*.h) $(wildcard crypto/*.S)
dkms-install: $(DKMS_TOP_LEVEL) $(DKMS_SELFTEST_LEVEL) $(DKMS_CRYPTO_LEVEL)
	@install -v -m0644 -D -t$(DESTDIR)$(DKMSDIR) $(DKMS_TOP_LEVEL)
	@install -v -m0644 -D -t$(DESTDIR)$(DKMSDIR)/selftest $(DKMS_SELFTEST_LEVEL)
	@install -v -m0644 -D -t$(DESTDIR)$(DKMSDIR)/crypto $(DKMS_CRYPTO_LEVEL)

tools:
	$(MAKE) -C tools

check:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN__" CONFIG_WIREGUARD_DEBUG=y
	$(MAKE) -C tools check

cloc: clean
	cloc $(filter-out compat.h, $(wildcard *.c) $(wildcard *.h))

-include tests/debug.mk

.PHONY: all module module-debug tools install dkms-install clean core-cloc check version.h dkms.conf
