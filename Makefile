CC      = gcc
CFLAGS  = -Iinclude -Wall -Wextra -g -O0
SRCS    = src/memory_bugs.c src/format_injection.c src/logic_bugs.c
OBJS    = $(SRCS:.c=.o)
TARGET  = vuln_demo

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
