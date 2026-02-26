CC = gcc
CFLAGS = -Wall -Wextra -fPIC -g -O2
LDFLAGS = -shared -ldl

all: build/oob-handler.so build/syscall-capture.so

build/oob-handler.so: src/oob-handler.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/syscall-capture.so: src/syscall-capture.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -rf build

.PHONY: all clean
