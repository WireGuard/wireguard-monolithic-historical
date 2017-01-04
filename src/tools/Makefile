PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
RUNSTATEDIR ?= /var/run
PKG_CONFIG ?= pkg-config
WITH_BASHCOMPLETION ?= yes

CFLAGS ?= -O3
CFLAGS += -std=gnu11
CFLAGS += -pedantic -Wall -Wextra
CFLAGS += -MMD -MP
CFLAGS += -DRUNSTATEDIR="\"$(RUNSTATEDIR)\""
LDLIBS += -lresolv
ifeq ($(shell uname -s),Linux)
LIBMNL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libmnl 2>/dev/null)
LIBMNL_LDLIBS := $(shell $(PKG_CONFIG) --libs libmnl 2>/dev/null || echo -lmnl)
CFLAGS += $(LIBMNL_CFLAGS)
LDLIBS += $(LIBMNL_LDLIBS)
endif

wg: $(patsubst %.c,%.o,$(wildcard *.c))

clean:
	rm -f wg *.o *.d

install: wg
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -m 0755 -v wg "$(DESTDIR)$(BINDIR)/wg"
	@install -v -d "$(DESTDIR)$(MANDIR)/man8" && install -m 0644 -v wg.8 "$(DESTDIR)$(MANDIR)/man8/wg.8"
	@[ "$(WITH_BASHCOMPLETION)" = "yes" ] && install -v -d "$(BASHCOMPDIR)" && install -m 0644 -v completion/wg.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/wg"

check: clean
	CFLAGS=-g scan-build --view --keep-going $(MAKE) wg

.PHONY: clean install check

-include *.d
