.DEFAULT_GOAL=default 
.PHONY=gen_lib_hex
.PRECIOUS: %.so

CC=gcc
LIB=-static -lm 
BUILD_TYPE=-O0 -g
CFLAGS= $(BUILD_TYPE) -std=c99 -fPIC -lpthread
TARGET=io_monitor
IO_MONITOR_OBJ=io_monitor.o opts.o 
IO_MONITOR_LIB=libio_read.so libio_write.so libio_both.so

debug: BUILD_TYPE:=-g3 
debug: default

test: main.c
	$(CC) main.c $(CFLAGS) -o $@ 

%.i: %.c 
	$(CC) -E $< $(CFLAGS) -o $@ 

%.o: %.c %.h
	$(CC) -c $< $(CFLAGS) -o $@ 

io_both.o: io_write.o io_read.o 
	$(CC) -c $(@:.o=.c) $(CFLAGS) -o $@ 

libio_both.so: libio_read.so libio_write.so misc.o io_both.o 
	$(CC) io_both.o misc.o $(CFLAGS) -o $@ -shared -ldl
	xxd -i $@ > $(@:.so=.hex)

lib%.so : %.o misc.o 
	$(CC) $^ $(CFLAGS) -o $@ -shared -ldl
	xxd -i $@ > $(@:.so=.hex)

io_monitor.o: $(IO_MONITOR_LIB) io_monitor.c 
	$(CC) -c $(@:.o=.c) $(CFLAGS) -o $@ 

io_monitor: $(IO_MONITOR_OBJ) 
	$(CC) $(IO_MONITOR_OBJ) $(CFLAGS) -o $@ 

default: $(TARGET)

cscope:
	find . -name "*.c" -o -name "*.h" > cscope.files 
	cscope -Rbq -i cscope.files

