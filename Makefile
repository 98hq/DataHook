CC = gcc
CFLAGS = -g -shared -fPIC -m32
LDFLAGS = -ldl

.PHONY: all

all: libdatahook.so libbasichook.so

libdatahook.so: main.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

libbasichook.so: hook.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.so
