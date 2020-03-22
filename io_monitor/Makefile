#=================================================
# Makefile settings
#=================================================
.DEFAULT_GOAL=default 
.PHONY=gen_lib_hex cscope obj_copy_libc # not consider this target dependency
.PRECIOUS: %.so # prevent make rm this intermediate files

#=================================================
# Compiler settings (:= make are expanded when they are defined rather than when they are used (=))
#=================================================
CC               = gcc
LIB              = -static -lm 
BUILD_TYPE       = -O0 -g
CFLAGS           = $(BUILD_TYPE) -std=c99 -fPIC -lpthread
TARGET           = io_monitor
IO_MONITOR_OBJ   = io_monitor.o opts.o 
IO_MONITOR_LIB   = libio_read.so libio_write.so libio_both.so
STATIC_LIBC_PATH = $(shell gcc --print-file-name=libc.a)
LIBC_PREFIX      = __static_libc_
LOCAL_LIBC_NAME  = libc_local.a

#=================================================
# Implicit Rules
#=================================================
%.i: %.c 
	$(CC) -E $< $(CFLAGS) -o $@ 

%.o: %.c %.h
	$(CC) -c $< $(CFLAGS) -o $@ 

lib%.so : %.o misc.o 
	$(CC) $^ $(CFLAGS) -o $@ $(LOCAL_LIBC_NAME) -shared -ldl
	xxd -i $@ > $(@:.so=.hex)

#=================================================
# Target Rules, target can abort with shell exit non-zero
#=================================================
debug: BUILD_TYPE:=-g3 
debug: default

test: main.c
	$(CC) main.c $(CFLAGS) -o $@ 


io_both.o: io_write.o io_read.o 
	$(CC) -c $(@:.o=.c) $(CFLAGS) -o $@ 

libio_both.so: libio_read.so libio_write.so misc.o io_both.o 
	$(CC) $(LOCAL_LIBC_NAME) io_both.o misc.o $(CFLAGS) -o $@ -shared -ldl
	xxd -i $@ > $(@:.so=.hex)

obj_copy_libc:
	@echo "====================================="
	@echo "pre-processing libc.a ..."
	@echo "libc.a=$(STATIC_LIBC_PATH)"
	objcopy --prefix-symbols=$(LIBC_PREFIX) $(STATIC_LIBC_PATH) $(LOCAL_LIBC_NAME); exit $$?
	@echo "====================================="
	
io_monitor.o: $(IO_MONITOR_LIB) io_monitor.c 
	$(CC) -c $(@:.o=.c) $(CFLAGS) -o $@ 

io_monitor: $(IO_MONITOR_OBJ) 
	$(CC) $(IO_MONITOR_OBJ) $(CFLAGS) -o $@ 

default: $(TARGET)

#=================================================
# Util
#=================================================
cscope:
	find . -name "*.c" -o -name "*.h" > cscope.files 
	cscope -Rbq -i cscope.files

