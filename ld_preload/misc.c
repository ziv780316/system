#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "misc.h"

void init_pid_info ( char *pid_info )
{
	pid_t tid;
	pid_t pid;
	tid = syscall( SYS_gettid ); 
	pid = syscall( SYS_getpid ); 
	if ( pid == tid )
	{
		sprintf( pid_info, "PID=%d", pid );
	}
	else
	{
		sprintf( pid_info, "PID=%d TID=%d", pid, tid );
	}

}

FILE *create_report_file ()
{
	char report_file[BUFSIZ];
	static int report_to_log = -1;
	if ( -1 == report_to_log )
	{
		if ( getenv("LD_PRELOAD_REPORT_TO_LOG") )
		{
			report_to_log = true;
		}
		else
		{
			report_to_log = false;
		}
	}
	if ( report_to_log )
	{
		pid_t pid;
		pid = syscall( SYS_getpid ); 
		sprintf( report_file, "/tmp/.report.%d", pid );
	}
	else
	{
		sprintf( report_file, "/dev/tty" );
	}

	FILE *fout = fopen( report_file, "a" );
	if ( !fout )
	{
		fprintf( stderr, "[Error] fopen fail in %s error=\"%s\"\n", __func__, strerror(errno) );
		abort();
	}

	setbuf( fout, 0 );
}


