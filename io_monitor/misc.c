#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <signal.h>
#include <execinfo.h>

#include "io_monitor.h"
#include "misc.h"

static int g_dump_type = DUMP_NONE;
static char *g_output_dir = NULL;
static pid_t g_io_monitor_pid = 1;

ssize_t (*libc_read) (int , void *, size_t) = NULL;
ssize_t (*libc_write) (int , const void *, size_t) = NULL;
int (*libc_fflush) (FILE *) = NULL;
int (*libc_fputc) (int, FILE *) = NULL;
int (*libc_printf) (const char*, ...) = NULL;
int (*libc_fprintf) (FILE *, const char*, ...) = NULL;
int (*libc_sprintf) (char *, const char*, ...) = NULL;
int (*libc_vprintf) (const char*, va_list) = NULL;
int (*libc_vsprintf) (char *, const char*, va_list) = NULL;
int (*libc_vfprintf) (FILE *, const char*, va_list) = NULL;

static sighandler_t register_signal_handler ( int signum, void (*fp) (int) )
{
	if ( SIG_ERR == signal( signum, fp ) )
	{
		libc_fprintf( stderr, "[Error] register signal fail -> %s\n", strerror(errno) );
		abort();
	}
}

static void sigsegv_backtrace ( int signum )
{
	pid_t tid = syscall( SYS_gettid ); 
	libc_fprintf( stderr, "[Warning] pid=%d get SIGSEGV\n", tid );

	__print_backtrace();
	signal( SIGSEGV, SIG_DFL );
	raise( SIGSEGV );
}

static void *dlsym_rtld_next ( char *name )
{
	void *fp = dlsym( RTLD_NEXT, name );
	if ( NULL == fp )
	{
		libc_fprintf( stderr, "[Error] RTLD link function %s fail -> %s\n", name, dlerror() );
		abort();
	}
}

static char *getenv_thread_save (const char *name)
{
	if ( (NULL == __environ) || ('\0' == name[0]) )
	{
		return NULL;
	}

	int name_len = 0;
	for ( int i = 0; name[i]; ++i )
	{
		++name_len;
	}

	char *ep;
	for ( int i = 0; __environ[i]; ++i )
	{
		ep = __environ[i];

		int ep_name_len = 0;
		for ( int j = 0; ep[j]; ++j )
		{
			if ( '=' == ep[j] )
			{
				break;
			}
			++ep_name_len;
		}
		if ( ep_name_len == name_len )
		{
			bool match = true;
			for ( int j = 0; j < ep_name_len; ++j )
			{
				if ( ep[j] != name[j] )
				{
					match = false;
				}
			}
			if ( match )
			{
				return &(ep[ep_name_len + 1]);
			}
		}
	}

	return NULL;
}

static void record_process_info ()
{
	// record command
	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/init.report", g_output_dir );
	FILE *fout = fopen( report_file, "a" );
	if ( !fout )
	{
		libc_fprintf( stderr, "[Error] fopen %s fail in %s -> %s\n", report_file, __func__, strerror(errno) );
		__print_backtrace();
	}
	char cmd[BUFSIZ];
	pid_t pid = syscall(SYS_getpid);
	pid_t ppid = syscall(SYS_getppid);
	__get_proc_cmd( cmd, pid );
	libc_fprintf( fout, "pid=%d ppid=%d cmd=%s\n", pid, ppid, cmd );
	fclose( fout );

	// copy env file
	//char environ_path[BUFSIZ];
	//libc_sprintf( environ_path, "/proc/%d/environ", pid );
	//FILE *fin = fopen( environ_path, "r" );
	//if ( !fin )
	//{
	//	libc_fprintf( stderr, "[Error] fopen %s fail in %s -> %s\n", environ_path, __func__, strerror(errno) );
	//	__print_backtrace();
	//}

	//libc_sprintf( report_file, "%s/environ.%d", g_output_dir, pid );
	//fout = fopen( report_file, "w" );
	//if ( !fout )
	//{
	//	libc_fprintf( stderr, "[Error] fopen %s fail in %s -> %s\n", report_file, __func__, strerror(errno) );
	//	__print_backtrace();
	//}

	//int ch;
	//while( EOF != (ch = fgetc( fin )) )
	//{
	//	if ( '\0' == ch )
	//	{
	//		libc_fputc( '\n', fout );
	//	}
	//	else
	//	{
	//		libc_fputc( ch, fout );
	//	}
	//}
	//fclose( fin );
	//fclose( fout );

	// trace parent command
	__print_all_parent_cmd( fout, pid, g_io_monitor_pid );

}


void __init_pid_info ( char *pid_info )
{
	pid_t tid;
	pid_t pid;
	tid = syscall( SYS_gettid ); 
	pid = syscall( SYS_getpid ); 
	if ( pid == tid )
	{
		libc_sprintf( pid_info, "PID=%d", pid );
	}
	else
	{
		libc_sprintf( pid_info, "PID=%d TID=%d", pid, tid );
	}

}

FILE *__create_report_file ( char *type, char *exec, char *event_file )
{
	char event_file_name_modify[BUFSIZ];
	strcpy( event_file_name_modify, event_file );
	for ( int i = 0; event_file_name_modify[i] != '\0' ; ++i )
	{
		if ( ('/' == event_file_name_modify[i]) ||
		     ('.' == event_file_name_modify[i]) )
		{
			event_file_name_modify[i] = '_';
		}
	}

	char exec_name_modify[BUFSIZ];
	strcpy( exec_name_modify, exec );
	for ( int i = 0; exec_name_modify[i] != '\0' ; ++i )
	{
		if ( ('/' == exec_name_modify[i]) ||
		     ('.' == exec_name_modify[i]) )
		{
			exec_name_modify[i] = '_';
		}
	}

	pid_t pid;
	pid = syscall( SYS_gettid ); // unique in multi-threading
	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/%s.report.%d.%s.%s", g_output_dir, type, pid, exec_name_modify, event_file_name_modify );

	FILE *fout = fopen( report_file, "a" );
	if ( !fout )
	{
		libc_fprintf( stderr, "[Error] fopen %s fail in %s -> %s\n", report_file, __func__, strerror(errno) );
		__print_backtrace();
	}

	return fout;
}

__attribute__((constructor))
void __init_monitor () 
{
	// bind origin libc function
	libc_fprintf = (int (*) (FILE *, const char *, ...)) dlsym_rtld_next( "fprintf" );
	libc_printf = (int (*) (const char *, ...)) dlsym_rtld_next( "printf" );
	libc_sprintf = (int (*) (char *, const char *, ...)) dlsym_rtld_next( "sprintf" );
	libc_vfprintf = (int (*) (FILE *, const char *, va_list)) dlsym_rtld_next( "vfprintf" );
	libc_vprintf = (int (*) (const char *, va_list)) dlsym_rtld_next( "vprintf" );
	libc_vsprintf = (int (*) (char *, const char *, va_list)) dlsym_rtld_next( "vsprintf" );
	libc_fflush = (int (*) (FILE *)) dlsym_rtld_next( "fflush" );
	libc_fputc = (int (*) (int, FILE *)) dlsym_rtld_next( "fputc" );
	libc_read = (ssize_t (*) (int , void *, size_t)) dlsym_rtld_next( "read" );
	libc_write = (ssize_t (*) (int , const void *, size_t)) dlsym_rtld_next( "write" );

	// get io_monitor spec
	char *env;
	env = getenv_thread_save( "IO_MONITOR_DUMP_TYPE" );
	if ( !env )
	{
		g_dump_type = DUMP_ASCII;
	}
	else
	{
		g_dump_type = atoi( env );
	}

	env = getenv_thread_save( "IO_MONITOR_REPORT_DIR" );
	if ( !env )
	{
		g_output_dir = strdup( "/tmp" );
	}
	else
	{
		g_output_dir = strdup( env );
	}

	env = getenv_thread_save( "IO_MONITOR_PID" );
	if ( env )
	{
		g_io_monitor_pid = atoi( env );
	}

	// register signal 
	register_signal_handler( SIGSEGV, sigsegv_backtrace );

	// record process information 
	record_process_info ();
}

void __print_all_parent_cmd ( FILE *fout, pid_t pid_start, pid_t pid_end )
{
	
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
					libc_fprintf( fout, "%c", ((char *)buf)[i] );
				}
				else
				{
					libc_fprintf( fout, "." );
				}
			}
			else if ( DUMP_HEX == g_dump_type )
			{
				libc_fprintf( fout, "%02hhx", ((unsigned char *)buf)[i] );
			}
		}
	}
}

void __get_proc_fd_name ( char *buf, pid_t pid, int fd )
{
	if ( 0 == fd )
	{
		strcpy( buf, "stdin" );
	}
	else if ( 1 == fd )
	{
		strcpy( buf, "stdout" );
	}
	else if ( 2 == fd )
	{
		strcpy( buf, "stderr" );
	}
	else
	{
		char file_name[BUFSIZ] = {0};
		char fd_link_path[BUFSIZ] = {0};
		libc_sprintf( fd_link_path, "/proc/%d/fd/%d", pid, fd );
		if ( -1 == readlink( fd_link_path, file_name, BUFSIZ ) )
		{
			libc_fprintf( stderr, "[Error] readlink %s fail in %s\n", fd_link_path, __func__ );
			abort();
		}
		strcpy( buf, file_name );
	}
}

void __get_proc_exec_name ( char *buf, pid_t pid )
{
	char exec_link_path[BUFSIZ] = {0};
	libc_sprintf( exec_link_path, "/proc/%d/cmdline", pid );
	FILE *fin = fopen( exec_link_path, "r" );
	if ( !fin )
	{
		libc_fprintf( stderr, "[Error] open %s fail in %s\n", exec_link_path, __func__ );
		abort();
	}

	char line[BUFSIZ] = {0};
	char arg[BUFSIZ];
	libc_read( fileno(fin), line, BUFSIZ );
	int i = 0;
	for ( ; line[i]; ++i )
	{
		arg[i] = line[i];
	}
	arg[i] = '\0';
	if ( (0 == strcmp("sh", arg )) || (0 == strcmp("csh", arg)) || (0 == strcmp("bash", arg)) )
	{
		char shell[BUFSIZ];
		strcpy( shell, arg );

		++i;
		while ( line[i] )
		{
			int j = 0;
			for ( ; line[i + j]; ++j )
			{
				arg[j] = line[i + j];
			}
			arg[j] = '\0';
			if ( '-' != arg[0] ) 
			{
				strcpy( buf, arg );
				return;
			}
			i += j + 1;
		}

		strcpy( buf, shell );
		return;
	}

	fclose( fin );
	strcpy( buf, arg );
	return;
}

void __get_proc_cmd ( char *cmd_buf, pid_t pid )
{
	char exec_link_path[BUFSIZ] = {0};
	libc_sprintf( exec_link_path, "/proc/%d/cmdline", pid );
	FILE *fin = fopen( exec_link_path, "r" );
	if ( !fin )
	{
		libc_fprintf( stderr, "[Error] open %s fail in %s\n", exec_link_path, __func__ );
		abort();
	}

	char line[BUFSIZ] = {0};
	ssize_t n_read = libc_read( fileno(fin), line, BUFSIZ );
	for ( int i = 0; i < n_read; ++i )
	{
		if ( '\0' == line[i] )
		{
			line[i] = ' ';
		}
	}
	
	fclose( fin );

	strcpy( cmd_buf, line );
}

void __print_backtrace ()
{
#define MAX_BACKTRACE_DEPTH 100
	void *buffer[MAX_BACKTRACE_DEPTH];
	int nptrs = backtrace( buffer, MAX_BACKTRACE_DEPTH );
	char **strings = backtrace_symbols( buffer, nptrs );
	if ( !strings )
	{
		libc_fprintf( stderr, "[Error] backtrace fail -> %s\n", strerror(errno) );
	}
	for ( int i = 0; i < nptrs; ++i )
	{
		libc_fprintf( stderr, "%s\n", strings[i] );
	}

	free( strings );
}

void exit ( int exit_code )  
{
	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/exit.report", g_output_dir );
	FILE *fout = fopen( report_file, "a" );
	if ( !fout )
	{
		libc_fprintf( stderr, "[Error] fopen %s fail in %s -> %s\n", report_file, __func__, strerror(errno) );
		__print_backtrace();
	}
	char cmd[BUFSIZ];
	pid_t pid = syscall(SYS_getpid);
	pid_t ppid = syscall(SYS_getppid);
	__get_proc_cmd( cmd, pid );
	libc_fprintf( fout, "exit=%d pid=%d ppid=%d cmd=%s\n", exit_code, pid, ppid, cmd );
	fclose( fout );

	void (*libc_exit) (int) = (void (*) (int)) dlsym_rtld_next( "exit" );
	libc_exit( exit_code );
}

void _exit ( int exit_code )  
{
	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/exit.report", g_output_dir );
	FILE *fout = fopen( report_file, "a" );
	if ( !fout )
	{
		libc_fprintf( stderr, "[Error] fopen %s fail in %s -> %s\n", report_file, __func__, strerror(errno) );
		__print_backtrace();
	}
	char cmd[BUFSIZ];
	pid_t pid = syscall(SYS_getpid);
	__get_proc_cmd( cmd, pid );
	libc_fprintf( fout, "_exit=%d pid=%d cmd=%s\n", exit_code, pid, cmd );
	fclose( fout );

	void (*libc_exit) (int) = (void (*) (int)) dlsym_rtld_next( "_exit" );
	libc_exit( exit_code );
}
