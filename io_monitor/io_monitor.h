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
	int tmpfile_fd;

	// IPC for all sub process, determine monitor type real-time
	unsigned int *ipc_monitor_flag;
#define IO_MONITOR_IPC_PROJ_ID 1 
#define IO_MONITOR_IPC_MONITOR_OFF    0x0
#define IO_MONITOR_IPC_MONITOR_READ   0x1
#define IO_MONITOR_IPC_MONITOR_WRITE  0x2
#define IO_MONITOR_IPC_MONITOR_PSTREE 0x4
#define IO_MONITOR_IPC_MONITOR_ENV    0x8
#define IO_MONITOR_IPC_MONITOR_ALL    0xffffffff

#define IO_MONITOR_USER_KEY_MONITOR_OFF       'o'
#define IO_MONITOR_USER_KEY_MONITOR_READ      'r'
#define IO_MONITOR_USER_KEY_MONITOR_WRITE     'w'
#define IO_MONITOR_USER_KEY_MONITOR_PSTREE    'p'
#define IO_MONITOR_USER_KEY_MONITOR_ENV       'e'
#define IO_MONITOR_USER_KEY_MONITOR_ALL       'a'
#define IO_MONITOR_USER_KEY_MONITOR_KILL      'k'

} monitor_t;

extern monitor_t g_monitor;

#endif

