CC			= gcc
WARN		= -Wall -Wextra 
STDC		= -std=gnu23
LIBS		= -lssl -lcrypto -largon2
INCLUDE		= -Isrc -I/usr/include

SRCS		= $(wildcard src/*.c)
OBJS		= $(SRCS:src/%.c=build/%.o)
PROGRAM		= lockf

PREFIX		?= /usr/local
BINDIR		= $(PREFIX)/bin

BUILD		?= release

ifeq ($(BUILD), debug)
	CFLAGS = $(WARN) $(INCLUDE) $(STDC) -O0 -g
	DEFINES = -DDEBUG

else ifeq ($(BUILD), release)
	CFLAGS = $(WARN) $(INCLUDE) $(STDC) -O3
	DEFINES = -DNDEBUG

else
	$(error Unknown build mode: $(BUILD))
endif

.PHONY: all clean install uninstall

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) $(DEFINES) $^ -o $@ $(LIBS)

build/%.o: src/%.c
	@mkdir -p build/
	$(CC) -c $(CFLAGS) $(DEFINES) $< -o $@

install:
	install -d $(BINDIR)
	install -m 755 $(PROGRAM) $(BINDIR)/$(PROGRAM)

uninstall:
	@if [ -f $(BINDIR)/$(PROGRAM) ]; then rm -f $(BINDIR)/$(PROGRAM); fi

clean:
	rm -rf build/ $(PROGRAM)
