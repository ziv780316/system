#=================================================
# Makefile settings
#=================================================
.DEFAULT_GOAL=default 
.PHONY=cscope init
.PRECIOUS: %.so # prevent make rm this intermediate files

#=================================================
# Compiler settings (:= make are expanded when they are defined rather than when they are used (=))
#=================================================
CC               = gcc
CXX              = g++
LINKER           = $(CC)
LIB              = -static -lm 
BUILD_TYPE       = -O0 -g
CFLAGS           = $(BUILD_TYPE) -std=c99 -fPIC
CXXFLAGS         = $(BUILD_TYPE) -std=c++11 -fPIC 
LDFLAGS          = -lpthread
TARGET           = io_monitor
IO_MONITOR_OBJ   = io_monitor.o opts.o 
IO_MONITOR_LIB   = libio_read.so libio_write.so libio_both.so
REPLACE_LIST     = replace_functions

#=================================================
# Implicit Rules
#=================================================
%.i: %.c 
	$(CC) -E $< $(CFLAGS) -o $@ 

%.i: %.cxx
	$(CXX) -E $< $(CXXFLAGS) -o $@ 

%.o: %.c %.h
	$(CC) -c $< $(CFLAGS) -o $@ 

%.o: %.cpp %.h
	$(CXX) -c $< $(CXXFLAGS) -o $@ 

lib%.so : %.o misc.o 
	$(LINKER) $^ $(LDFLAGS) -o $@ -shared -ldl
	xxd -i $@ > $(@:.so=.hex)
	

#=================================================
# Target Rules, target can abort with shell exit non-zero
#=================================================
debug: BUILD_TYPE:=-g3 
debug: default

test: main.c
	$(CC) main.c $(CFLAGS) -o $@ 

io_monitor.o: $(IO_MONITOR_LIB) io_monitor.c 
	$(CC) -c $(@:.o=.c) $(CFLAGS) -o $@ 

io_monitor: init $(IO_MONITOR_OBJ) 
	$(LINKER) $(IO_MONITOR_OBJ) $(LDFLAGS) -o $@ 

init: misc.o
	rm -f $(REPLACE_LIST)
	echo "const char *$(REPLACE_LIST)[] = {" >> $(REPLACE_LIST)
	grep '^\S\+\s\+\*\?(\*libc_\(\S\+\))\s*(.*NULL;' $(<:.o=.c) | sed 's/^\S\+\s\+\*\?(\*libc_\(\S\+\))\s*(.*NULL;/"\1",/' >> $(REPLACE_LIST)
	echo 'NULL};' >> $(REPLACE_LIST)

default: $(TARGET)

#=================================================
# Util
#=================================================
cscope:
	find . -name "*.c" -o -name "*.h" > cscope.files 
	cscope -Rbq -i cscope.files

