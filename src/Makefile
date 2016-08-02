KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: module tools
debug: module-debug tools

module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

module-debug:
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
	cloc ./*.c ./*.h

include tests/debug.mk

.PHONY: all module module-debug tools install clean core-cloc check
