CC := gcc
CFLAGS := -O2 -Wall $(shell pkg-config --cflags libnetfilter_queue)
LDLIBS := $(shell pkg-config --libs libnetfilter_queue)

all: nfqnl

nfqnl: nfqnl.o
	$(CC) $^ $(LDLIBS) -o $@

nfqnl.o: nfqnl.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f nfqnl *.o