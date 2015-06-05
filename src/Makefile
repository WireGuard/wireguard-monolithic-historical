ifneq ($(KERNELRELEASE),)
ifneq ($(KBUILD_EXTMOD),)
CONFIG_WIREGUARD := m
endif

obj-$(CONFIG_WIREGUARD) := wireguard.o
ccflags-y := -O3 -fvisibility=hidden
ccflags-$(CONFIG_WIREGUARD_DEBUG) := -DDEBUG -g
ifneq ($(KBUILD_EXTMOD),)
ifeq ($(CONFIG_WIREGUARD_PARALLEL),)
ifneq (,$(filter $(CONFIG_PADATA),y m))
ccflags-y += -DCONFIG_WIREGUARD_PARALLEL=y
endif
endif
endif

wireguard-y := main.o noise.o device.o peer.o timers.o data.o send.o receive.o socket.o config.o hashtables.o routing-table.o ratelimiter.o cookie.o
wireguard-y += crypto/curve25519.o crypto/chacha20poly1305.o crypto/blake2s.o crypto/siphash24.o
ifeq ($(CONFIG_X86_64),y)
	wireguard-y += crypto/chacha20-ssse3-x86_64.o crypto/poly1305-sse2-x86_64.o
avx2_supported := $(call as-instr,vpgatherdd %ymm0$(comma)(%eax$(comma)%ymm1$(comma)4)$(comma)%ymm2,yes,no)
ifeq ($(avx2_supported),yes)
	wireguard-y += crypto/chacha20-avx2-x86_64.o crypto/poly1305-avx2-x86_64.o
endif
endif
else
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

core-cloc: clean
	cloc ./*.c ./*.h

check:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) C=2 CF="-D__CHECK_ENDIAN__" CONFIG_WIREGUARD_DEBUG=y

include debug.mk

.PHONY: all module module-debug tools install clean core-cloc check
endif
