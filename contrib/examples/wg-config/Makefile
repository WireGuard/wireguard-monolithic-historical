PREFIX ?= /usr
DESTDIR ?=
SBINDIR ?= $(PREFIX)/sbin

SCRIPTS := wg-config tungate

all:
	@echo "These are shell scripts, so there is nothing to do. Try \"make install\" instead."

install:
	@install -v -m0755 -D -t$(DESTDIR)$(SBINDIR) $(SCRIPTS)

.PHONY: all install
