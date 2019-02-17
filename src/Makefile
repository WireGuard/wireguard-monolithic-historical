# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PREFIX ?= /usr
DESTDIR ?=
SRCDIR ?= $(PREFIX)/src
DKMSDIR ?= $(SRCDIR)/wireguard
DEPMOD ?= depmod

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
	$(DEPMOD) -a

install: module-install tools-install

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
DKMS_SOURCES := version.h Makefile Kbuild Kconfig dkms.conf $(filter-out version.h wireguard.mod.c tools/% tests/%,$(call rwildcard,,*.c *.h *.S *.pl *.include))
dkms-install: $(DKMS_SOURCES)
	@$(foreach f,$(DKMS_SOURCES),install -v -m0644 -D $(f) $(DESTDIR)$(DKMSDIR)/$(f);)

tools:
	@$(MAKE) -C tools

tools-debug:
	@$(MAKE) -C tools V=1 DEBUG_TOOLS=y

tools-install:
	@$(MAKE) -C tools install

style:
	$(KERNELDIR)/scripts/checkpatch.pl -f --max-line-length=4000 --codespell --color=always $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h) $(wildcard selftest/*.c)

check: clean
	scan-build --html-title=WireGuard -maxloop 100 --view --keep-going $(MAKE) module tools CONFIG_WIREGUARD_DEBUG=y C=2 CF="-D__CHECK_ENDIAN__"

coccicheck: clean
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_WIREGUARD_DEBUG=y coccicheck MODE=report

cloc:
	@cloc --skip-uniqueness --by-file --extract-with="$$(readlink -f ../contrib/kernel-tree/filter-compat-defines.sh) >FILE< > \$$(basename >FILE<)" $(filter-out wireguard.mod.c,$(wildcard *.c)) $(wildcard *.h)

-include tests/debug.mk

.PHONY: all module module-debug module-install tools tools-install install dkms-install clean core-cloc check style version.h dkms.conf
