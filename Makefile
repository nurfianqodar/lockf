CC			= gcc
CFLAGS		= -Wall -Wextra -O0 -g -std=gnu23
LDFLAGS		= -lssl -lcrypto -largon2
INCLUDE		= -Isrc -I/usr/include

SRCS		= $(wildcard src/*.c)
OBJS		= $(SRCS:src/%.c=build/%.o)
TARGET		= build/lockf

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDE) $(LDFLAGS)

build/%.o: src/%.c
	@mkdir -p build/
	$(CC) -c $(CFLAGS) $< -o $@ $(INCLUDE)

clean:
	rm -rf build/
