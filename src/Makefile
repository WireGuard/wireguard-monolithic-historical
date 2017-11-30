# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DKMSDIR ?= $(SRCDIR)/wireguard

PWD := $(shell pwd)

all: module tools
debug: module-debug tools-debug

ifneq ($(V),1)
MAKEFLAGS += --no-print-directory
endif

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
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

module-debug: version.h
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) V=1 CONFIG_WIREGUARD_DEBUG=y modules

clean:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@$(MAKE) -C tools clean

module-install:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a

install:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a
	@$(MAKE) -C tools install

DKMS_TOP_LEVEL := Makefile Kbuild Kconfig $(filter-out wireguard.mod.c, $(wildcard *.c)) $(filter-out version.h, $(wildcard *.h)) version.h dkms.conf
DKMS_SELFTEST_LEVEL := $(wildcard selftest/*.c) $(wildcard selftest/*.h)
DKMS_CRYPTO_LEVEL := $(wildcard crypto/*.c) $(wildcard crypto/*.h) $(wildcard crypto/*.S)
DKMS_UAPI_LEVEL := $(wildcard uapi/*.h)
DKMS_COMPAT_LEVEL := $(shell find compat/ -name '*.c' -o -name '*.h' -o -name '*.include')
dkms-install: $(DKMS_TOP_LEVEL) $(DKMS_SELFTEST_LEVEL) $(DKMS_CRYPTO_LEVEL) $(DKMS_UAPI_LEVEL) $(DKMS_COMPAT_LEVEL)
	@install -v -m0644 -D -t$(DESTDIR)$(DKMSDIR) $(DKMS_TOP_LEVEL)
	@install -v -m0644 -D -t$(DESTDIR)$(DKMSDIR)/selftest $(DKMS_SELFTEST_LEVEL)
	@install -v -m0644 -D -t$(DESTDIR)$(DKMSDIR)/crypto $(DKMS_CRYPTO_LEVEL)
	@install -v -m0644 -D -t$(DESTDIR)$(DKMSDIR)/uapi $(DKMS_UAPI_LEVEL)
	@for file in $(DKMS_COMPAT_LEVEL); do install -v -m0644 -D $$file $(DESTDIR)$(DKMSDIR)/$$file; done

tools:
	@$(MAKE) -C tools

tools-debug:
	@$(MAKE) -C tools V=1 DEBUG_TOOLS=y

style:
	$(KERNELDIR)/scripts/checkpatch.pl -f --max-line-length=4000 --codespell --color=always $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h)

check: clean
	scan-build --view --keep-going $(MAKE) module tools CONFIG_WIREGUARD_DEBUG=y C=2 CF="-D__CHECK_ENDIAN__"

coccicheck: clean
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_WIREGUARD_DEBUG=y coccicheck MODE=report

cloc:
	@cloc --skip-uniqueness --by-file --extract-with="$$(readlink -f ../contrib/kernel-tree/filter-compat-defines.sh) >FILE< > \$$(basename >FILE<)" $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h)

-include tests/debug.mk

.PHONY: all module module-debug module-install tools install dkms-install clean core-cloc check style version.h dkms.conf
