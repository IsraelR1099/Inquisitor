# Variables

CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic -g
LDFLAGS := -lpcap
SRCS := arp.c utils.c signals.c set_headers.c
OBJS := $(SRCS:.c=.o)
DEPS := inquisitor.h
TARGET := inquisitor

# Rules

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

re: clean all

.PHONY: all clean re
