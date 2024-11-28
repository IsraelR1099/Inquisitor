# Variables

CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic -lpthread -g
LDFLAGS := -lpcap -lpthread
SRCS := arp.c \
		utils.c \
		signals.c \
		set_headers.c \
		sniffer_ftp.c \
		forward_packet.c \
		restore_arp.c
OBJS := $(SRCS:.c=.o)
DEPS := inquisitor.h
TARGET := inquisitor

# Rules

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	docker build -t arp -f Dockerfile .

run:
	docker-compose -f docker-compose.yaml up

down:
	docker-compose -f docker-compose.yaml down

clean:
	rm -f $(OBJS) $(TARGET)

re: clean all

.PHONY: all clean re
