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

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

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

void __init_monitor ()
{
	pthread_mutex_lock( &g_mutex );

	static bool initialized = false;
	if ( !initialized )
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

		// get io_monitor spec
		char *env;
		env = getenv_thread_save( "IO_MONITOR_DUMP_TYPE" );
		if ( !env )
		{
			libc_fprintf( stderr, "[Warning] getenv IO_MONITOR_DUMP_TYPE fail, use type ascii\n" );
			g_dump_type = DUMP_ASCII;
		}
		else
		{
			libc_fprintf( stderr, "[io_monitor] getenv IO_MONITOR_DUMP_TYPE=%s\n", env );
			g_dump_type = atoi( env );
		}

		env = getenv_thread_save( "IO_MONITOR_REPORT_DIR" );
		if ( !env )
		{
			libc_fprintf( stderr, "[Error] getenv IO_MONITOR_DUMP_TYPE fail, use /tmp\n" );
			g_output_dir = strdup( "/tmp" );
		}
		else
		{
			libc_fprintf( stderr, "[io_monitor] getenv IO_MONITOR_REPORT_DIR=%s\n", env );
			g_output_dir = strdup( env );
		}

		// register signal 
		register_signal_handler( SIGSEGV, sigsegv_backtrace );

		initialized = true;
	}

	pthread_mutex_unlock( &g_mutex );
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
		libc_sprintf( fd_link_path, "/proc/%d/fd/%d", pid, fd );
		if ( -1 == readlink( fd_link_path, file_name, BUFSIZ ) )
		{
			libc_fprintf( stderr, "[Error] readlink %s fail in %s\n", fd_link_path, __func__ );
			abort();
		}
		return strdup( file_name );
	}
}

char *__get_proc_exec_name ( pid_t pid )
{
	char exec_name[BUFSIZ] = {0};
	char exec_link_path[BUFSIZ] = {0};
	libc_sprintf( exec_link_path, "/proc/%d/cmdline", pid );
	FILE *fin = fopen( exec_link_path, "r" );
	if ( !fin )
	{
		libc_fprintf( stderr, "[Error] open %s fail in %s\n", exec_link_path, __func__ );
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
			libc_sprintf( arg, "%s", pos );
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
	fclose( fin );

	return strdup( exec );
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
