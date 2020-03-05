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
#include <fcntl.h>

#include "io_monitor.h"
#include "opts.h"

// store pre-compile .so
#include "libio_read.hex" 
#include "libio_write.hex" 

monitor_t g_monitor;

FILE *create_tmp_file ()
{
	char tmpfile_name[BUFSIZ];
	sprintf( tmpfile_name, "/tmp/.libXXXXXX" );
	mkstemp( tmpfile_name );
	if ( NULL == tmpfile_name )
	{
		fprintf( stderr, "[error] create tmpfile name fail -> %s\n", strerror(errno) );
		abort();
	}
	sprintf( tmpfile_name, "%s.so", tmpfile_name );

	int fd = open( tmpfile_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU );
	if ( -1 == fd )
	{
		fprintf( stderr, "[error] create tmpfile %s fail -> %s\n", tmpfile_name, strerror(errno) );
		abort();
	}

	g_monitor.tmpfile_name = strdup( tmpfile_name );
	g_monitor.tmpfile_fd = fd;
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
	}
}

void set_ld_preload_lib ( char *lib )
{
	if ( -1 == setenv( "LD_PRELOAD", lib, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"LD_PRELOAD\" fail -> %s\n", strerror(errno) );
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

		create_tmp_file();
		dump_pre_compile_lib();
		printf( "* Monitor information:\n" );
		printf( "cmd = %s\n", g_opts.cmd );
		printf( "tmp_library = %s\n", g_monitor.tmpfile_name );

		int status;
		pid_t pid;
		if ( 0 == (pid = fork()) )
		{
			set_ld_preload_lib( g_monitor.tmpfile_name );

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

