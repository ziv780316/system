#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <dlfcn.h>

#include "misc.h"

ssize_t write ( int fd, const void *buf, size_t n )
{
	pthread_mutex_lock( &g_mutex_write );

	// get information from monitor 
	__init_monitor();

	ssize_t status;	
	status = syscall( SYS_write, fd, buf, n );
	int errno_store = errno;	

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	pid_t pid = syscall( SYS_getpid ); 
	char *file_name = __get_proc_fd_name( pid, fd );
	char *exec_name = __get_proc_exec_name( pid );
	FILE *fout = __create_report_file( "write", exec_name, file_name );

	if ( -1 == status )
	{
		libc_fprintf( fout, "[write] process=%s exec=%s write fd=%d file=\"%s\" status=fail error=\"%s\"\n", pid_info, exec_name, fd, file_name, strerror(errno_store) );
	}
	else
	{
		ssize_t n_write = status;
		libc_fprintf( fout, "[write] process=%s exec=%s write fd=%d file=\"%s\" bytes=%ld status=ok\n", pid_info, exec_name, fd, file_name, n_write );
		if ( n_write > 0 )
		{
			// non EOF
			__dump_data_to_report ( fout, buf, n_write );
		}
	}
	
	fclose( fout );

	pthread_mutex_unlock( &g_mutex_write );

	return status;
}

int fflush ( FILE *stream )
{
	pthread_mutex_lock( &g_mutex_fflush );

	// get information from monitor 
	__init_monitor();

	char *write_ptr = stream->_IO_write_ptr;
	char *write_base = stream->_IO_write_base;

	int status = libc_fflush( stream );
	int errno_store = errno;	

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno %s fail in %s -> %s\n", __func__, strerror(errno) );
		return status;
	}

	pid_t pid = syscall( SYS_getpid ); 
	char *file_name = __get_proc_fd_name( pid, fd );
	char *exec_name = __get_proc_exec_name( pid );
	FILE *fout = __create_report_file( "fflush", exec_name, file_name );

	if ( fout )
	{
		if ( 0 != status )
		{
			libc_fprintf( fout, "[fflush] process=%s exec=%s fflush fd=%d file=\"%s\" status=fail error=\"%s\"\n", pid_info, exec_name, fd, file_name, strerror(errno_store) );
		}
		else
		{
			ssize_t n_write = write_ptr - write_base;
			libc_fprintf( fout, "[fflush] process=%s exec=%s fflush fd=%d file=\"%s\" bytes=%ld status=ok\n", pid_info, exec_name, fd, file_name, n_write );
			if ( n_write > 0 )
			{
				// non EOF
				__dump_data_to_report ( fout, (void *)write_base, n_write );
			}
		}
		fclose( fout );
	}

	pthread_mutex_unlock( &g_mutex_fflush );

	return status;
}

int fputc ( int c, FILE *stream )
{
	pthread_mutex_lock( &g_mutex_fputc ); 

	// get information from monitor 
	__init_monitor();

	int status = libc_fputc( c, stream );
	int errno_store = errno;	

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno %s fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
		return status;
	}

	pid_t pid = syscall( SYS_getpid ); 
	char *file_name = __get_proc_fd_name( pid, fd );
	char *exec_name = __get_proc_exec_name( pid );
	FILE *fout = __create_report_file( "fputc", exec_name, file_name );

	__dump_data_to_report ( fout, (void *)&c, 1 );
	fclose( fout );

	pthread_mutex_unlock( &g_mutex_fputc );

	return status;
}
