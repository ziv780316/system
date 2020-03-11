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
#include <stdarg.h>

#include "misc.h"

ssize_t write ( int fd, const void *buf, size_t n )
{
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


	return status;
}

int fflush ( FILE *stream )
{
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


	return status;
}

int fputc ( int c, FILE *stream )
{
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

	if ( fout )
	{
		if ( EOF == status )
		{
			// error
		}
		else
		{
			libc_fputc( c, fout );
		}
	}

	fclose( fout );

	return status;
}

int printf ( const char *fmt, ... )
{
	// get information from monitor 
	__init_monitor();

	va_list va;
	va_start( va, fmt );

	int status = libc_printf( fmt, va );
	int errno_store = errno;	

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stdout );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno %s fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
		return status;
	}

	pid_t pid = syscall( SYS_getpid ); 
	char *file_name = __get_proc_fd_name( pid, fd );
	char *exec_name = __get_proc_exec_name( pid );
	FILE *fout = __create_report_file( "printf", exec_name, file_name );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_fprintf( fout, fmt, va );
		}
	}

	fclose( fout );

	return status;
}

int fprintf ( FILE *stream, const char *fmt, ... )
{
	// get information from monitor 
	__init_monitor();

	va_list va;
	va_start( va, fmt );

	int status = libc_fprintf( stream, fmt, va );
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
	FILE *fout = __create_report_file( "fprintf", exec_name, file_name );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_fprintf( fout, fmt, va );
		}
	}

	fclose( fout );

	return status;
}

int sprintf ( char *buf, const char *fmt, ... )
{
	// get information from monitor 
	__init_monitor();

	va_list va;
	va_start( va, fmt );

	int status = libc_sprintf( buf, fmt, va );
	int errno_store = errno;	

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );
	pid_t pid = syscall( SYS_getpid ); 
	char *exec_name = __get_proc_exec_name( pid );
	FILE *fout = __create_report_file( "sprintf", exec_name, "buf" );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_fprintf( fout, fmt, va );
		}
	}

	fclose( fout );

	return status;
}
