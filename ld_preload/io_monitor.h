#ifndef IO_H
#define IO_H

#include <stdio.h>
#include <stdbool.h>

typedef enum {
	MONITOR_NONE,
	MONITOR_READ,
	MONITOR_WRITE,
	MONITOR_BOTH,
} monitor_type_t;

typedef enum {
	DUMP_NONE,
	DUMP_ASCII,
	DUMP_HEX,
} dump_type_t;

typedef struct
{
	char *tmpfile_name_read;
	char *tmpfile_name_write;
	int tmpfile_fd_read;
	int tmpfile_fd_write;
	dump_type_t dump_type;
	monitor_type_t monitor_type;
	bool debug;
} monitor_t;

extern monitor_t g_monitor;

#endif

