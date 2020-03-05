#ifndef IO_H
#define IO_H

#include <stdio.h>

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
	char *tmpfile_name;
	int tmpfile_fd;
	dump_type_t dump_type;
	monitor_type_t monitor_type;
} monitor_t;

extern monitor_t g_monitor;

extern void init_pid_info ( char *pid_info );
extern FILE *create_report_file ();

#endif

