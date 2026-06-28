CC = gcc
CFLAGS = -Iinclude -Wall -Wextra -g -O0

.PHONY: all clean

all: src/memory_bugs.o src/format_injection.o src/logic_bugs.o
	@echo "Build complete"

src/memory_bugs.o: src/memory_bugs.c
	$(CC) $(CFLAGS) -c src/memory_bugs.c -o src/memory_bugs.o

src/format_injection.o: src/format_injection.c
	$(CC) $(CFLAGS) -c src/format_injection.c -o src/format_injection.o

src/logic_bugs.o: src/logic_bugs.c
	$(CC) $(CFLAGS) -c src/logic_bugs.c -o src/logic_bugs.o

clean:
	rm -f src/*.o
