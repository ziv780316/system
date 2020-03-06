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

#include "io_monitor.h"
#include "opts.h"

// store pre-compile .so
#include "libio_read.hex" 
#include "libio_write.hex" 

monitor_t g_monitor;

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
		n_write = write( g_monitor.tmpfile_fd_read, libio_read_so, libio_read_so_len );
		if ( n_write != libio_read_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_read_so_len=%d, dump libio_read.so to %s (fd=%d) fail -> %s\n", n_write, libio_read_so_len, g_monitor.tmpfile_name_read, g_monitor.tmpfile_fd_read, strerror(errno) );
			abort();
		}
	}
	else if ( MONITOR_WRITE == g_opts.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd_write, libio_write_so, libio_write_so_len );
		if ( n_write != libio_write_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_write_so_len=%d, dump libio_write.so to %s (fd=%d) fail -> %s\n", n_write, libio_write_so_len, g_monitor.tmpfile_name_write, g_monitor.tmpfile_fd_write, strerror(errno) );
			abort();
		}
	}
	else if ( MONITOR_BOTH == g_opts.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd_read, libio_read_so, libio_read_so_len );
		if ( n_write != libio_read_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_read_so_len=%d, dump libio_read.so to %s (fd=%d) fail -> %s\n", n_write, libio_read_so_len, g_monitor.tmpfile_name_read, g_monitor.tmpfile_fd_read, strerror(errno) );
			abort();
		}

		n_write = write( g_monitor.tmpfile_fd_write, libio_write_so, libio_write_so_len );
		if ( n_write != libio_write_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_write_so_len=%d, dump libio_write.so to %s (fd=%d) fail -> %s\n", n_write, libio_write_so_len, g_monitor.tmpfile_name_write, g_monitor.tmpfile_fd_write, strerror(errno) );
			abort();
		}
	}
}

void set_ld_preload_lib ()
{
	char env[BUFSIZ];
	if ( MONITOR_READ == g_opts.monitor_type )
	{
		sprintf( env, "%s", g_monitor.tmpfile_name_read );
	}
	else if ( MONITOR_WRITE == g_opts.monitor_type )
	{
		sprintf( env, "%s", g_monitor.tmpfile_name_write );
	}
	else if ( MONITOR_BOTH == g_opts.monitor_type )
	{
		sprintf( env, "%s:%s", g_monitor.tmpfile_name_read, g_monitor.tmpfile_name_write );
	}

	if ( -1 == setenv( "LD_PRELOAD", env, 1 ) ) // overwrite
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

		// tmp file is preload .so
		if ( MONITOR_READ == g_monitor.monitor_type)
		{
			create_tmp_file( &(g_monitor.tmpfile_fd_read), &(g_monitor.tmpfile_name_read) );
		}
		else if ( MONITOR_WRITE == g_monitor.monitor_type)
		{
			create_tmp_file( &(g_monitor.tmpfile_fd_write), &(g_monitor.tmpfile_name_write) );
		}
		else if ( MONITOR_BOTH == g_monitor.monitor_type)
		{
			create_tmp_file( &(g_monitor.tmpfile_fd_read), &(g_monitor.tmpfile_name_read) );
			create_tmp_file( &(g_monitor.tmpfile_fd_write), &(g_monitor.tmpfile_name_write) );
		}

		// dump .so
		dump_pre_compile_lib();

		// create directory to collect report
		create_dir( g_opts.output_dir );

		printf( "* Monitor information:\n" );
		printf( "monitor cmd  = %s\n", g_opts.cmd );
		if ( MONITOR_READ == g_monitor.monitor_type )
		{
			printf( "tmp read.so  = %s\n", g_monitor.tmpfile_name_read );
		}
		else if ( MONITOR_WRITE == g_monitor.monitor_type )
		{
			printf( "tmp wrie.so  = %s\n", g_monitor.tmpfile_name_write );
		}
		else if ( MONITOR_BOTH == g_monitor.monitor_type )
		{
			printf( "tmp read.so  = %s\n", g_monitor.tmpfile_name_read );
			printf( "tmp write.so = %s\n", g_monitor.tmpfile_name_write );
		}
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

	if ( MONITOR_READ == g_monitor.monitor_type )
	{
		remove( g_monitor.tmpfile_name_read );
	}
	else if ( MONITOR_WRITE == g_monitor.monitor_type )
	{
		remove( g_monitor.tmpfile_name_write );
	}
	else if ( MONITOR_BOTH == g_monitor.monitor_type )
	{
		remove( g_monitor.tmpfile_name_read );
		remove( g_monitor.tmpfile_name_write );
	}

	return EXIT_SUCCESS;
}

