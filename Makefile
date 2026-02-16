CC			= gcc
WARN		= -Wall -Wextra 
STDC		= -std=gnu23
LDFLAGS		= -lssl -lcrypto -largon2
INCLUDE		= -Isrc -I/usr/include

SRCS		= $(wildcard src/*.c)
OBJS		= $(SRCS:src/%.c=build/%.o)
TARGET		= build/lockf

BUILD		?= debug

ifeq ($(BUILD), debug)
	CFLAGS = $(WARN) $(INCLUDE) $(STDC) -O0 -g
	DEFINES = -DDEBUG
else ifeq ($(BUILD), release)
	CFLAGS = $(WARN) $(INCLUDE) $(STDC) -O2
	DEFINES = -DNDEBUG
else
	$(error Unknown build mode: $(BUILD))
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(DEFINES) $^ -o $@ $(LDFLAGS)

build/%.o: src/%.c
	@mkdir -p build/
	$(CC) -c $(CFLAGS) $(DEFINES) $< -o $@
clean:
	rm -rf build/
