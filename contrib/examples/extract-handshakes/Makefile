ifeq ($(KERNELRELEASE),)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CFLAGS ?= -O3 -march=native
CFLAGS += -Wall -pedantic -std=gnu11

offsets.include: offset-finder
	./$^ > $@

offset-finder: offset-finder.c offset-finder.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

offset-finder.o: offset-finder.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@
	objcopy -j '.rodata*' $@ $@

clean:
	rm -f offset-finder offsets.include
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: clean
else
offset-finder-m := offset-finder.o
oldsrc := $(src)
src := $(src)/../../../src
include $(src)/compat/Kbuild.include
src := $(oldsrc)
endif
