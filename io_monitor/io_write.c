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
#include <fcntl.h>

#include "misc.h"

ssize_t write ( int fd, const void *buf, size_t n )
{
	__link_libc_functions();
	__sync_ipc();

	if ( *g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_FILE )
	{
		char report_file[BUFSIZ];
		libc_sprintf( report_file, "%s/fopen.report", g_output_dir );
		FILE *fout = libc_fopen( report_file, "a" );
		pid_t pid = getpid(); 
		char file_name[BUFSIZ];
		__get_proc_fd_name( file_name, pid, fd );
		char *time_str = __get_time_string();
		int flags = fcntl(fd, F_GETFL);
		char *flags_str;
		if ( (flags & 0x00000003) == O_RDONLY ) { flags_str = "r"; };
		if ( (flags & 0x00000003) == O_WRONLY ) { flags_str = "w"; };
		if ( (flags & 0x00000003) == O_RDWR ) { flags_str = "w+"; };

		libc_fprintf( fout, "write=%s byte=%d flags=%s time=%s pid=%d\n", file_name, n, flags_str, time_str, pid );
		libc_fclose( fout );
	}

	ssize_t status;	
	status = libc_write( fd, buf, n );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}
	if ( -1 == fd )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	__get_proc_exec_name( exec_name, pid );

	FILE *fout = __create_report_file( "write", exec_name, file_name );

	if ( fout )
	{
		if ( -1 == status )
		{
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

		libc_fclose( fout );
	}

	return status;
}

size_t fwrite ( const void *buf, size_t size, size_t nmemb, FILE *stream )
{
	__link_libc_functions();
	__sync_ipc();

	ssize_t status;	
	status = libc_fwrite( buf, size, nmemb, stream );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "fwrite", exec_name, file_name );

	if ( fout )
	{
		if ( 0 == status )
		{
		}
		else
		{
			ssize_t n_write = nmemb * size;
			libc_fprintf( fout, "[fwrite] process=%s exec=%s fwrite fd=%d file=\"%s\" bytes=%ld status=ok\n", pid_info, exec_name, fd, file_name, n_write );
			if ( n_write > 0 )
			{
				// non EOF
				__dump_data_to_report ( fout, buf, n_write );
			}
		}

		libc_fclose( fout );
	}

	return status;
}

#ifdef IO_MONITOR_FFLUSH
int fflush ( FILE *stream )
{
	__link_libc_functions();
	__sync_ipc();

	char *write_ptr = stream->_IO_write_ptr;
	char *write_base = stream->_IO_write_base;

	int status = libc_fflush( stream );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		return status;
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "fflush", exec_name, file_name );

	if ( fout )
	{
		if ( 0 != status )
		{
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
		libc_fclose( fout );
	}

	return status;
}
#endif

int fputc ( int c, FILE *stream )
{
	__link_libc_functions();
	__sync_ipc();

	int status = libc_fputc( c, stream );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	if ( -1 == fd )
	{
		strcpy( file_name, "?" );
	}
	else
	{
		__get_proc_fd_name( file_name, pid, fd );
	}
	__get_proc_exec_name( exec_name, pid );
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

		libc_fclose( fout );
	}

	return status;
}

int fputs ( const char *s, FILE *stream )
{
	__link_libc_functions();
	__sync_ipc();

	int status = libc_fputs( s, stream );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	if ( -1 == fd )
	{
		strcpy( file_name, "?" );
	}
	else
	{
		__get_proc_fd_name( file_name, pid, fd );
	}
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "fputs", exec_name, file_name );

	if ( fout )
	{
		if ( EOF == status )
		{
			// error
		}
		else
		{
			libc_fputs( s, fout );
		}

		libc_fclose( fout );
	}

	return status;
}

int printf ( const char *fmt, ... )
{
	__link_libc_functions();
	__sync_ipc();

	va_list va, va_origin;
	va_start( va, fmt );
	va_copy( va_origin , va );

	int status = libc_vprintf( fmt, va );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stdout );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
		return status;
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "printf", exec_name, "stdout" );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_vfprintf( fout, fmt, va_origin );
		}

		libc_fclose( fout );
	}

	va_end( va );

	return status;
}

int fprintf ( FILE *stream, const char *fmt, ... )
{
	__link_libc_functions();
	__sync_ipc();

	va_list va, va_origin;
	va_start( va, fmt );
	va_copy( va_origin , va );

	int status = libc_vfprintf( stream, fmt, va );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );
	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
		return status;
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "fprintf", exec_name, file_name );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_vfprintf( fout, fmt, va_origin );
		}

		libc_fclose( fout );
	}

	va_end( va );

	return status;
}

int sprintf ( char *buf, const char *fmt, ... )
{
	__link_libc_functions();
	__sync_ipc();

	va_list va, va_origin;
	va_start( va, fmt );
	va_copy( va_origin , va );

	int status = libc_vsprintf( buf, fmt, va );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	pid_t pid = getpid(); 
	char exec_name[BUFSIZ];
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "sprintf", exec_name, "buf" );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_vfprintf( fout, fmt, va_origin );
		}

		libc_fclose( fout );
	}

	va_end( va );

	return status;
}

int vprintf ( const char *fmt, va_list va )
{
	__link_libc_functions();
	__sync_ipc();

	va_list va_origin;
	va_copy( va_origin, va );

	int status = libc_vprintf( fmt, va );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stdout );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
		return status;
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	 __get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "vprintf", exec_name, "stdout" );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_vfprintf( fout, fmt, va_origin );
		}

		libc_fclose( fout );
	}

	return status;
}

int vsprintf ( char *buf, const char *fmt, va_list va )
{
	__link_libc_functions();
	__sync_ipc();

	va_list va_origin;
	va_copy( va_origin, va );

	int status = libc_vsprintf( buf, fmt, va );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	pid_t pid = getpid(); 
	char exec_name[BUFSIZ];
	 __get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "vsprintf", exec_name, "buf" );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_vfprintf( fout, fmt, va_origin );
		}

		libc_fclose( fout );
	}

	return status;
}

int vfprintf ( FILE *stream, const char *fmt, va_list va )
{
	__link_libc_functions();
	__sync_ipc();

	va_list va_origin;
	va_copy( va_origin, va );

	int status = libc_vfprintf( stream, fmt, va );
	int errno_store = errno;	
	if ( !(*g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_WRITE) || !__is_in_monitor_list(__func__) )
	{
		return status;
	}

	// show information that monitor file write by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	int fd = fileno( stream );

	if ( -1 == fd )
	{
		libc_fprintf( stderr, "[Error] fileno fail in %s -> %s\n", __func__, strerror(errno) );
		__print_backtrace();
		return status;
	}

	pid_t pid = getpid(); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "vfprintf", exec_name, file_name );

	if ( fout )
	{
		if ( status < 0 )
		{
			// error
		}
		else
		{
			libc_vfprintf( fout, fmt, va_origin );
		}

		libc_fclose( fout );
	}

	return status;
}
