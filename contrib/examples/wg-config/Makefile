PREFIX ?= /usr
DESTDIR ?=
SBINDIR ?= $(PREFIX)/sbin

all:
	@echo "This is a shell script, so there is nothing to do. Try \"make install\" instead."

install:
	@install -v -m0755 -D -t$(DESTDIR)$(SBINDIR) wg-config

.PHONY: all install
