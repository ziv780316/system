.DEFAULT_GOAL=default 
.PHONY= gen_lib_hex

CC=gcc
LIB=-static -lm
CFLAGS= -O0 -std=c99 -fPIC
TARGET=io_monitor
IO_MONITOR_OBJ=io_monitor.o opts.o

test: main.c
	$(CC) main.c $(CFLAGS) -o $@ 

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@ 

libremove.so: remove.o misc.o
	$(CC) $^ $(CFLAGS) -o $@ -shared -ldl

lib%.so : %.c misc.o
	$(CC) $^ $(CFLAGS) -o $@ -shared -ldl

io_monitor: gen_lib_hex $(IO_MONITOR_OBJ) 
	$(CC) $(IO_MONITOR_OBJ) $(CFLAGS) -o $@ 

gen_lib_hex: libio_read.so libio_write.so 
	xxd -i libio_read.so > libio_read.hex
	xxd -i libio_write.so > libio_write.hex

default: $(TARGET)

cscope:
	find . -name "*.c" -o -name "*.h" > cscope.files 
	cscope -Rbq -i cscope.files

