KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: module tools
debug: module-debug tools

version.h:
	@export GIT_CEILING_DIRECTORIES="$$(readlink -f ../..)" && \
	ver="#define WIREGUARD_VERSION \"$$(git describe --dirty 2>/dev/null)\"" && \
	[ "$$(cat version.h 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.h && \
	git update-index --assume-unchanged version.h || true

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

tools:
	$(MAKE) -C tools

check:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN__" CONFIG_WIREGUARD_DEBUG=y
	$(MAKE) -C tools check

cloc: clean
	cloc $(filter-out compat.h, $(wildcard *.c) $(wildcard *.h))

include tests/debug.mk

.PHONY: all module module-debug tools install clean core-cloc check version.h
