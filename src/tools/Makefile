PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
SYSTEMDUNITDIR ?= $(shell $(PKG_CONFIG) --variable=systemdsystemunitdir systemd 2>/dev/null || echo "$(PREFIX)/lib/systemd/system")
RUNSTATEDIR ?= /var/run
WITH_BASHCOMPLETION ?=
WITH_WGQUICK ?=
WITH_SYSTEMDUNITS ?=

ifeq ($(WITH_BASHCOMPLETION),)
ifneq ($(strip $(wildcard $(DESTDIR)$(BASHCOMPDIR))),)
WITH_BASHCOMPLETION := yes
endif
endif
ifeq ($(WITH_WGQUICK),)
ifneq ($(strip $(wildcard $(DESTDIR)$(BINDIR)/bash)),)
WITH_WGQUICK := yes
endif
ifneq ($(strip $(wildcard $(DESTDIR)/bin/bash)),)
WITH_WGQUICK := yes
endif
endif
ifeq ($(WITH_SYSTEMDUNITS),)
ifneq ($(strip $(wildcard $(DESTDIR)$(SYSTEMDUNITDIR))),)
WITH_SYSTEMDUNITS := yes
endif
endif

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
	@[ "$(WITH_BASHCOMPLETION)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(BASHCOMPDIR)" && install -m 0644 -v completion/wg.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/wg"
	@[ "$(WITH_WGQUICK)" = "yes" ] || exit 0; \
	install -m 0755 -v wg-quick.bash "$(DESTDIR)$(BINDIR)/wg-quick"
	@[ "$(WITH_WGQUICK)" = "yes" ] || exit 0; \
	install -m 0644 -v wg-quick.8 "$(DESTDIR)$(MANDIR)/man8/wg-quick.8"
	@[ "$(WITH_WGQUICK)" = "yes" -a "$(WITH_BASHCOMPLETION)" = "yes" ] || exit 0; \
	install -m 0644 -v completion/wg-quick.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/wg-quick"
	@[ "$(WITH_WGQUICK)" = "yes" -a "$(WITH_SYSTEMDUNITS)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(SYSTEMDUNITDIR)" && install -m 0644 -v wg-quick@.service "$(DESTDIR)$(SYSTEMDUNITDIR)/wg-quick@.service"

check: clean
	CFLAGS=-g scan-build --view --keep-going $(MAKE) wg

help:
	@cat INSTALL

.PHONY: clean install check help

-include *.d
