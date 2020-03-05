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

FILE *create_report_file ( char *type, char *event_file )
{
	char report_file[BUFSIZ];
	char *event_file_name_modify = strdup( event_file );
	for ( int i = 0; event_file_name_modify[i] != '\0' ; ++i )
	{
		if ( ('/' == event_file_name_modify[i]) ||
		     ('.' == event_file_name_modify[i]) )
		{
			event_file_name_modify[i] = '_';
		}
	}
	pid_t pid;
	pid = syscall( SYS_getpid ); 
	sprintf( report_file, "%s/%s.report.%d.%s", "/tmp/io_monitor_db", type, pid, event_file_name_modify );

	FILE *fout = fopen( report_file, "a" );
	if ( !fout )
	{
		fprintf( stderr, "[Error] fopen %s fail -> %s\n", report_file, strerror(errno) );
		abort();
	}

	return fout;
}
