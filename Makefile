CC      = gcc
CFLAGS  = -Iinclude -Wall -Wextra -g -O0

SRCS    = src/memory_bugs.c src/format_injection.c src/logic_bugs.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean

all: $(OBJS)
	@echo "Build complete - object files ready for CodeQL analysis"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $

clean:
	rm -f $(OBJS)
