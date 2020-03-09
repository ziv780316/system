#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <execinfo.h>
#include <gnu/libc-version.h>

#include "io_monitor.h"
#include "opts.h"

// store pre-compile .so
#include "libio_read.hex" 
#include "libio_write.hex" 
#include "libio_both.hex" 

monitor_t g_monitor;


static sighandler_t register_signal_handler ( int signum, void (*fp) (int) )
{
	struct sigaction new_action, old_action;
	new_action.sa_handler = fp;
	sigemptyset( &new_action.sa_mask );
	new_action.sa_flags = 0;
	if ( -1 == sigaction( signum, NULL, &old_action ) )
	{
		fprintf( stderr, "[Error] sigaction get old action fail -> %s\n", strerror(errno) );
		abort();
	}
	if ( -1 == sigaction( signum, &new_action, NULL ) )
	{
		fprintf( stderr, "[Error] sigaction register fail -> %s\n", strerror(errno) );
		abort();
	}
}

static void sigsegv_backtrace ( int signum )
{
	pid_t tid = syscall( SYS_gettid ); 
	fprintf( stderr, "[Warning] pid=%d get SIGSEGV\n", tid );

#define MAX_BACKTRACE_DEPTH 100
	void *buffer[MAX_BACKTRACE_DEPTH];
	int nptrs = backtrace( buffer, MAX_BACKTRACE_DEPTH );
	char **strings = backtrace_symbols( buffer, nptrs );
	if ( !strings )
	{
		fprintf( stderr, "[Error] backtrace fail -> %s\n", strerror(errno) );
	}
	for ( int i = 0; i < nptrs; ++i )
	{
		fprintf( stderr, "%s\n", strings[i] );
	}

	free( strings );
	exit( 1 );
}

void create_tmp_file ( int *tmpfile_fd, char **ptmpfile_name )
{
	char *tmpfile_name = (char *) calloc( BUFSIZ, sizeof(char) );
	sprintf( tmpfile_name, "/tmp/.libXXXXXX" );
	mkstemp( tmpfile_name );
	if ( NULL == tmpfile_name )
	{
		fprintf( stderr, "[error] create tmpfile name fail -> %s\n", strerror(errno) );
		abort();
	}
	char so_name[BUFSIZ];
	sprintf( so_name, "%s.so", tmpfile_name );

	int fd = open( so_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU );
	if ( -1 == fd )
	{
		fprintf( stderr, "[error] create tmpfile %s fail -> %s\n", so_name, strerror(errno) );
		abort();
	}

	*ptmpfile_name = strdup( so_name );
	*tmpfile_fd = fd;
}


void dump_pre_compile_lib ()
{
	int n_write;
	if ( MONITOR_READ == g_opts.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd, libio_read_so, libio_read_so_len );
		if ( n_write != libio_read_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_read_so_len=%d, dump libio_read.so to %s (fd=%d) fail -> %s\n", n_write, libio_read_so_len, g_monitor.tmpfile_name, g_monitor.tmpfile_fd, strerror(errno) );
			abort();
		}
	}
	else if ( MONITOR_WRITE == g_opts.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd, libio_write_so, libio_write_so_len );
		if ( n_write != libio_write_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_write_so_len=%d, dump libio_write.so to %s (fd=%d) fail -> %s\n", n_write, libio_write_so_len, g_monitor.tmpfile_name, g_monitor.tmpfile_fd, strerror(errno) );
			abort();
		}
	}
	else if ( MONITOR_BOTH == g_opts.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd, libio_both_so, libio_both_so_len );
		if ( n_write != libio_both_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_both_so_len=%d, dump libio_both.so to %s (fd=%d) fail -> %s\n", n_write, libio_both_so_len, g_monitor.tmpfile_name, g_monitor.tmpfile_fd, strerror(errno) );
			abort();
		}
	}
}

void set_ld_preload_lib ()
{
	if ( -1 == setenv( "LD_PRELOAD", g_monitor.tmpfile_name, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"LD_PRELOAD\" fail -> %s\n", strerror(errno) );
		abort();
	}
}

void set_options_in_env ()
{
	char buf[BUFSIZ];
	sprintf( buf, "%d", g_monitor.dump_type );
	if ( -1 == setenv( "IO_MONITOR_DUMP_TYPE", buf, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"IO_MONITOR_DUMP_TYPE\" fail -> %s\n", strerror(errno) );
		abort();
	}
	sprintf( buf, "%s", g_opts.output_dir );
	if ( -1 == setenv( "IO_MONITOR_REPORT_DIR", buf, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"IO_MONITOR_REPORT_DIR\" fail -> %s\n", strerror(errno) );
		abort();
	}
}

void create_dir ( char *dir )
{
	if( (-1 == mkdir( dir, S_IRWXU )) && (EEXIST != errno) )
	{
		fprintf( stderr, "[Error] create directory \"%s\" fail -> %s\n", dir, strerror(errno) );
		abort();
	}
}

int main ( int argc, char **argv )
{
	if ( 1 == argc )
	{
		show_help();
	}
	else
	{
		// getopt parse command line arguments
		parse_cmd_options ( argc, argv );

		// register signal action for debug child
		register_signal_handler( SIGSEGV, sigsegv_backtrace );

		// tmp file is preload .so
		create_tmp_file( &(g_monitor.tmpfile_fd), &(g_monitor.tmpfile_name) );

		// dump .so
		dump_pre_compile_lib();

		// create directory to collect report
		create_dir( g_opts.output_dir );

		printf( "* Monitor information:\n" );
		printf( "libc version = %s\n", gnu_get_libc_version() );
		printf( "monitor cmd  = %s\n", g_opts.cmd );
		printf( "tmp so       = %s\n", g_monitor.tmpfile_name );
		printf( "report_dir   = %s\n", g_opts.output_dir );

		int status;
		pid_t pid;
		if ( 0 == (pid = fork()) )
		{
			// set LD_PRELOAD
			set_ld_preload_lib();

			// send dump type and report dir to child
			set_options_in_env();

			// child execute with sh has patter expasion (i.e. *)
			execlp( "/bin/sh", "sh", "-c", (const char *)g_opts.cmd, (char *) NULL );

			// exec return only in fail
			fprintf( stderr, "[Error] exec fail -> %s\n", strerror(errno) );
			abort();
		}
		else
		{
			// parent
			waitpid( pid, &status, 0 );
		}
	}

	remove( g_monitor.tmpfile_name );

	return EXIT_SUCCESS;
}

