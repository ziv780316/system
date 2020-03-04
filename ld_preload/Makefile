.DEFAULT_GOAL=default 

CC=gcc
LIB=-static -lm
CFLAGS= -O0 -std=c99 -fPIC
TARGET=test libremove.so libio.so

test: main.c
	$(CC) main.c $(CFLAGS) -o $@ 

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@ 

libremove.so: remove.o misc.o
	$(CC) $^ $(CFLAGS) -o $@ -shared -ldl

libio.so: io.c misc.o
	$(CC) $^ $(CFLAGS) -o $@ -shared -ldl

default: $(TARGET)

cscope:
	find . -name "*.c" -o -name "*.h" > cscope.files 
	cscope -Rbq -i cscope.files

