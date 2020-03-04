.DEFAULT_GOAL=default 

CC=gcc
LIB=-static -lm
CFLAGS= -O0 -std=c99 -fPIC
TARGET=test libremove.so

test: 
	$(CC) main.c $(CFLAGS) -o $@ 

libremove.so: 
	$(CC) remove.c $(CFLAGS) -o $@ -shared -ldl

default: $(TARGET)

cscope:
	find . -name "*.c" -o -name "*.h" > cscope.files 
	cscope -Rbq -i cscope.files

