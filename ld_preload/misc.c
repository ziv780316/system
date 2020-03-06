#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "io_monitor.h"
#include "misc.h"

static int g_dump_type = DUMP_NONE;
static char *g_output_dir = NULL;

void __init_pid_info ( char *pid_info )
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

FILE *__create_report_file ( char *type, char *exec, char *event_file )
{
	char *event_file_name_modify = strdup( event_file );
	for ( int i = 0; event_file_name_modify[i] != '\0' ; ++i )
	{
		if ( ('/' == event_file_name_modify[i]) ||
		     ('.' == event_file_name_modify[i]) )
		{
			event_file_name_modify[i] = '_';
		}
	}

	char *exec_name_modify = strdup( exec );
	for ( int i = 0; exec_name_modify[i] != '\0' ; ++i )
	{
		if ( ('/' == exec_name_modify[i]) ||
		     ('.' == exec_name_modify[i]) )
		{
			exec_name_modify[i] = '_';
		}
	}

	pid_t pid;
	pid = syscall( SYS_getpid ); 
	char report_file[BUFSIZ];
	sprintf( report_file, "%s/%s.report.%d.%s.%s", g_output_dir, type, pid, exec_name_modify, event_file_name_modify );

	FILE *fout = fopen( report_file, "a" );
	if ( !fout )
	{
		fprintf( stderr, "[Error] fopen %s fail -> %s\n", report_file, strerror(errno) );
		abort();
	}

	return fout;
}

void __init_monitor ()
{
	static bool initialized = false;
	if ( !initialized )
	{
		char *env;
		env = getenv( "IO_MONITOR_DUMP_TYPE" );
		if ( !env )
		{
			fprintf( stderr, "[Error] getenv IO_MONITOR_DUMP_TYPE fail\n" );
			abort();
		}
		g_dump_type = atoi( env );

		env = getenv( "IO_MONITOR_REPORT_DIR" );
		if ( !env )
		{
			fprintf( stderr, "[Error] getenv IO_MONITOR_DUMP_TYPE fail\n" );
			abort();
		}
		g_output_dir = strdup( env );

		initialized = true;
	}
}

void __dump_data_to_report ( FILE *fout, const void *buf, size_t n_bytes )
{
	if ( DUMP_NONE != g_dump_type )
	{
		for ( ssize_t i = 0; i < n_bytes; ++i )
		{
			if ( DUMP_ASCII == g_dump_type )
			{
				if ( ((char *)buf)[i] <= 128 )
				{
					fprintf( fout, "%c", ((char *)buf)[i] );
				}
				else
				{
					fprintf( fout, "." );
				}
			}
			else if ( DUMP_HEX == g_dump_type )
			{
				fprintf( fout, "%02hhx", ((unsigned char *)buf)[i] );
			}
		}
	}
}

char *__get_proc_fd_name ( pid_t pid, int fd )
{
	if ( 0 == fd )
	{
		return strdup( "stdin" );
	}
	else if ( 1 == fd )
	{
		return strdup( "stdout" );
	}
	else if ( 2 == fd )
	{
		return strdup( "stderr" );
	}
	else
	{
		char file_name[BUFSIZ] = {0};
		char fd_link_path[BUFSIZ] = {0};
		sprintf( fd_link_path, "/proc/%d/fd/%d", pid, fd );
		if ( -1 == readlink( fd_link_path, file_name, BUFSIZ ) )
		{
			fprintf( stderr, "[Error] readlink %s fail in %s\n", fd_link_path, __func__ );
			abort();
		}
		return strdup( file_name );
	}
}

char *__get_proc_exec_name ( pid_t pid )
{
	char exec_name[BUFSIZ] = {0};
	char exec_link_path[BUFSIZ] = {0};
	sprintf( exec_link_path, "/proc/%d/cmdline", pid );
	FILE *fin = fopen( exec_link_path, "r" );
	if ( !fin )
	{
		fprintf( stderr, "[Error] open %s fail in %s\n", exec_link_path, __func__ );
		abort();
	}
	char cmd_buf[BUFSIZ] = {0};
	fgets( cmd_buf, BUFSIZ, fin );

	char exec[BUFSIZ];
	char *pos = cmd_buf;
	sscanf( cmd_buf, "%s", exec );
	if ( (0 == strcmp("sh", exec )) || (0 == strcmp("csh", exec)) )
	{
		// command is -> sh -c program
		char arg[BUFSIZ];
		strcpy( arg, cmd_buf );
		while ( true )
		{
			pos += strlen(arg) + 1;
			sprintf( arg, "%s", pos );
			if ( '\0' == *arg ) 
			{
				break;
			}
			else if ( '-' != *arg ) 
			{
				sscanf( arg, "%s", exec ); // ignore ' '
				break;
			}
		}
	}

	return strdup( exec );
}
