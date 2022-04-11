#ifndef IO_H
#define IO_H

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

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
	char *cmd;
	char *tmp_so_name;
	char *result_dir;
	dump_type_t dump_type;
	monitor_type_t monitor_type;
	bool debug;
	pid_t child_pid;
	int shm_id;
	int shm_size;
	int tmpfile_fd;
	int n_monitor_function;

	// IPC for all sub process, determine monitor type real-time
	unsigned int *ipc_monitor_flag;
#define IO_MONITOR_IPC_PROJ_ID 1 
#define IO_MONITOR_IPC_MONITOR_STOP   0x1
#define IO_MONITOR_IPC_MONITOR_OFF    0x2
#define IO_MONITOR_IPC_MONITOR_READ   0x4
#define IO_MONITOR_IPC_MONITOR_WRITE  0x8
#define IO_MONITOR_IPC_MONITOR_PSTREE 0x10
#define IO_MONITOR_IPC_MONITOR_ENV    0x20
#define IO_MONITOR_IPC_MONITOR_REMOVE 0x40
#define IO_MONITOR_IPC_MONITOR_FILE 0x80
#define IO_MONITOR_IPC_MONITOR_ALL (IO_MONITOR_IPC_MONITOR_READ|IO_MONITOR_IPC_MONITOR_WRITE|IO_MONITOR_IPC_MONITOR_PSTREE|IO_MONITOR_IPC_MONITOR_ENV|IO_MONITOR_USER_KEY_MONITOR_REMOVE|IO_MONITOR_IPC_MONITOR_FILE)

#define IO_MONITOR_USER_KEY_MONITOR_CONTINUE   'c'
#define IO_MONITOR_USER_KEY_MONITOR_STOP       's'
#define IO_MONITOR_USER_KEY_MONITOR_OFF        'o'
#define IO_MONITOR_USER_KEY_MONITOR_READ       'r'
#define IO_MONITOR_USER_KEY_MONITOR_WRITE      'w'
#define IO_MONITOR_USER_KEY_MONITOR_PSTREE     'p'
#define IO_MONITOR_USER_KEY_MONITOR_ENV        'e'
#define IO_MONITOR_USER_KEY_MONITOR_REMOVE     'm'
#define IO_MONITOR_USER_KEY_MONITOR_ALL        'a'
#define IO_MONITOR_USER_KEY_MONITOR_KILL       'k'
#define IO_MONITOR_USER_KEY_MONITOR_UNREGISTER 'u'
#define IO_MONITOR_USER_KEY_MONITOR_FILE       'f'

	char *ipc_monitor_functions;
} monitor_t;

extern monitor_t g_monitor;

#endif

