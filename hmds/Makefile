CC      = gcc
CFLAGS  = -g -O0 -Wall -Werror -std=gnu11 -lz
LDFLAGS = -L.

.PHONY : all test clean

all: hmds

libhdb.a: hdb.o
	ar rcs libhdb.a hdb.o

hdb.o: hdb.c hdb.h
	$(CC) $(CFLAGS) -o $@ -c $<

testlibhdb: libhdb.a testlibhdb.o
	$(CC) -o $@ $^ $(LDFLAGS) -lhdb -lcheck -lhiredis -lm -lpthread -lrt -lz

testlibhdb.o: testlibhdb.c hdb.h
	$(CC) $(CFLAGS) -o $@ -c $<

test: testlibhdb
	./testlibhdb

client: client.c
	$(CC)  $(CFLAGS) -o $@ client.c -lz

hmds: hmds.c
	$(CC) $(CFLAGS) -o	$@ $(LDFLAGS) hmds.c -lhdb

clean:
	rm -f *.o *.a testlibhdb
