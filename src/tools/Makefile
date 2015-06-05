PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man

CFLAGS += -std=gnu11
CFLAGS += -pedantic -Wall -Wextra
CFLAGS += -MMD
LDLIBS += -lresolv -lmnl

wg: $(patsubst %.c,%.o,$(wildcard *.c))

clean:
	rm -f wg *.o *.d

install: wg
	install -v -d "$(DESTDIR)$(BINDIR)" && install -s -m 0755 -v wg "$(DESTDIR)$(BINDIR)/wg"
	install -v -d "$(DESTDIR)$(MANDIR)/man8" && install -m 0644 -v wg.8 "$(DESTDIR)$(MANDIR)/man8/wg.8"

check: clean
	CFLAGS=-g scan-build --view --keep-going $(MAKE) wg

.PHONY: clean install check

-include *.d
