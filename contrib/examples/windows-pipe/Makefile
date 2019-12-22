CC := x86_64-w64-mingw32-gcc
CFLAGS ?= -O3
CFLAGS += -Wall
enumerate-and-get.exe: enumerate-and-get.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<
clean:
	rm -f enumerate-and-get.exe
.PHONY: clean
