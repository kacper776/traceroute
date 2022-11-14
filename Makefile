CC = gcc
CFLAGS = -std=gnu17 -Wall -Wextra -Werror

OBJS = traceroute.o main.o

all: traceroute

traceroute: $(OBJS)
	$(CC) $(CFLAGS) -o traceroute $(OBJS)

traceroute.o: traceroute.c traceroute.h
main.o: main.c traceroute.h

clean:
	rm -f *.o

distclean:
	rm -f *.o traceroute