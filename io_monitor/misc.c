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
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/shm.h>

#include "misc.h"

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_dump_type = DUMP_NONE;
static char *g_output_dir = NULL;
static pid_t g_io_monitor_pid = 1;
static int g_io_monitor_shm_id;
unsigned int *g_ipc_monitor_flag = NULL;

ssize_t (*libc_read) (int , void *, size_t) = NULL;
ssize_t (*libc_write) (int , const void *, size_t) = NULL;
size_t (*libc_fwrite) (const void *, size_t, size_t, FILE *) = NULL;
int (*libc_fflush) (FILE *) = NULL;
int (*libc_fputc) (int, FILE *) = NULL;
int (*libc_fputs) (const char *, FILE *) = NULL;
int (*libc_printf) (const char*, ...) = NULL;
int (*libc_fprintf) (FILE *, const char*, ...) = NULL;
int (*libc_sprintf) (char *, const char*, ...) = NULL;
int (*libc_vprintf) (const char*, va_list) = NULL;
int (*libc_vsprintf) (char *, const char*, va_list) = NULL;
int (*libc_vfprintf) (FILE *, const char*, va_list) = NULL;
void (*libc_exit) (int) = NULL;
void (*libc__exit) (int) = NULL;

static FILE *fopen_w_check ( const char *name, const char *mode )
{
	FILE *stream = fopen( name, mode );
	if ( !stream )
	{
		if ( ENAMETOOLONG == errno )
		{
			char truncated_name[BUFSIZ];
			strcpy( truncated_name, name );
			truncated_name[NAME_MAX - 1] = '\0';
			stream = fopen( truncated_name, mode );
			libc_fprintf( stderr, "[Warning] truncate file from %d length to name %s\n", strlen(name), truncated_name );
			if ( !stream )
			{
				libc_fprintf( stderr, "[Error] fopen %s fail -> %s\n", truncated_name, strerror(errno) );
				__print_backtrace();
			}
		}
		else
		{
			libc_fprintf( stderr, "[Error] fopen %s fail -> %s\n", name, strerror(errno) );
			__print_backtrace();
		}
	}
	return stream;
}

static sighandler_t register_signal_handler ( int signum, void (*fp) (int) )
{
	if ( SIG_ERR == signal( signum, fp ) )
	{
		libc_fprintf( stderr, "[Error] register signal fail -> %s\n", strerror(errno) );
		libc_exit(1);
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
		syscall( SYS_exit, 1 );
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

static void run_shell_command_and_get_results ( char **output_str, const char *cmd )
{
	int status;
	pid_t pid;
	int fd[2]; // 0 is read, 1 is write

	if( -1 == pipe( fd ) )
	{
		libc_fprintf( stderr, "[Error] create pipe %s fail -> %s\n", strerror(errno) );
		libc_exit(1);
	}

	if ( 0 == (pid = fork()) )
	{
		unsetenv( "LD_PRELOAD" ); 

		close( fd[0] );
		if( -1 == dup2( fd[1], STDOUT_FILENO ) )
		{
			libc_fprintf( stderr, "[Error] dup2 fail -> %s\n", strerror(errno) );
			libc_exit(1);
		}

		// child execute with sh has patter expasion (i.e. *)
		execlp( "/bin/sh", "sh", "-c", (const char *)cmd, (char *) NULL );

		// exec return only in fail
		libc_fprintf( stderr, "[Error] run_shell_command %s fail -> %s\n", cmd, strerror(errno) );
		libc_exit(1);
	}
	else
	{
		// parent
		close( fd[1] );
		waitpid( pid, &status, 0 );
	}

	ssize_t n_read;
	size_t str_size = 1;
	char buf[BUFSIZ];
	*output_str = (char *) calloc ( 1, 1 );
	while ( true )
	{
		n_read = syscall( SYS_read, fd[0], (void *)buf, BUFSIZ );
		if ( n_read > 0 )
		{
			*output_str = realloc( *output_str, str_size + n_read );
			if ( NULL == *output_str )
			{
				fprintf( stderr, "[Error] run_shell_command %s realloc fail fail -> %s\n", cmd, strerror(errno) );
				exit(1);
			}
			memcpy( (char *)(*output_str) + str_size - 1, buf, n_read );
			str_size += n_read;
			(*output_str)[str_size - 1] = '\0';
		}
		else if ( -1 == n_read )
		{
			libc_fprintf( stderr, "[Error] run_shell_command %s read pipe fail -> %s\n", cmd, strerror(errno) );
			libc_exit(1);
		}
		else if ( 0 == n_read )
		{
			// EOF
			break;
		}

	}
	close( fd[0] );
}

static void run_shell_command ( const char *cmd )
{
	int status;
	pid_t pid;
	if ( 0 == (pid = fork()) )
	{
		unsetenv( "LD_PRELOAD" ); 

		// child execute with sh has patter expasion (i.e. *)
		execlp( "/bin/sh", "sh", "-c", (const char *)cmd, (char *) NULL );

		// exec return only in fail
		libc_fprintf( stderr, "[Error] run_shell_command %s fail -> %s\n", cmd, strerror(errno) );
		libc_exit(1);
	}
	else
	{
		// parent
		waitpid( pid, &status, 0 );
	}
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

	FILE *fout = fopen_w_check( report_file, "a" );

	return fout;
}

// ==================================================
// monitor setup
// ==================================================
void __record_process_info ()
{
	// necessary in this stage for convenience
	libc_sprintf = (int (*) (char *, const char *, ...)) dlsym_rtld_next( "sprintf" ); 
	libc_fprintf = (int (*) (FILE*, const char *, ...)) dlsym_rtld_next( "fprintf" ); 

	// record pid and command
	pid_t pid = syscall( SYS_getpid );
	pid_t ppid = syscall( SYS_getppid );
	char exec_cmd[BUFSIZ];
	char *exec_result;
	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/init.report", g_output_dir );
	FILE *fout = fopen_w_check( report_file, "a" );
	if ( fout )
	{
		libc_sprintf( exec_cmd, "cat /proc/%d/cmdline | tr '\\0' ' '", pid );
		run_shell_command_and_get_results( &exec_result, exec_cmd );
		libc_fprintf( fout, "pid=%d ppid=%d cmd=%s", pid, ppid, exec_result );

		libc_sprintf( exec_cmd, "cat /proc/%d/cmdline | tr '\\0' ' '", ppid );
		run_shell_command_and_get_results( &exec_result, exec_cmd );
		libc_fprintf( fout, " parent_cmd=%s\n", exec_result );

		free( exec_result );
		fclose( fout );
	}

	// backtrace process tree 
	if ( *g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_PSTREE )
	{
		libc_sprintf( exec_cmd, "pstree -apsnl %d >> %s/pstree.%d", pid, g_output_dir, pid );
		run_shell_command( exec_cmd );
	}

	// dump process env
	if ( *g_ipc_monitor_flag & IO_MONITOR_IPC_MONITOR_ENV )
	{
		libc_sprintf( exec_cmd, "cat /proc/%d/environ | tr '\\0' '\\n' > %s/environ.%d", pid, g_output_dir, pid );
		run_shell_command( exec_cmd );
	}
}

__attribute__((constructor))
void __init_monitor ()
{
	if ( g_ipc_monitor_flag )
	{
		// already initialized
		return;
	}

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

	env = getenv_thread_save( "IO_MONITOR_SHM_ID" );
	if ( env )
	{
		g_io_monitor_shm_id = atoi( env );
	}

	// get real time control share memory
	g_ipc_monitor_flag = (unsigned int *) shmat( g_io_monitor_shm_id, NULL, 0 );
	if ( !g_ipc_monitor_flag )
	{
		fprintf( stderr, "[Error] shmat get data fail -> %s\n", strerror(errno) );
		exit(1);
	}

	// register signal 
	register_signal_handler( SIGSEGV, sigsegv_backtrace );

	__record_process_info();
}

void __link_libc_functions ()
{
	pthread_mutex_lock( &g_mutex );

	if ( !g_ipc_monitor_flag  )
	{
		__init_monitor();
	}

	static bool initialized = false;
	if ( !initialized )
	{
		initialized = true;

		// bind origin libc function
		libc_fprintf = (int (*) (FILE *, const char *, ...)) dlsym_rtld_next( "fprintf" );
		libc_printf = (int (*) (const char *, ...)) dlsym_rtld_next( "printf" );
		libc_sprintf = (int (*) (char *, const char *, ...)) dlsym_rtld_next( "sprintf" );
		libc_vfprintf = (int (*) (FILE *, const char *, va_list)) dlsym_rtld_next( "vfprintf" );
		libc_vprintf = (int (*) (const char *, va_list)) dlsym_rtld_next( "vprintf" );
		libc_vsprintf = (int (*) (char *, const char *, va_list)) dlsym_rtld_next( "vsprintf" );
		libc_fflush = (int (*) (FILE *)) dlsym_rtld_next( "fflush" );
		libc_fputc = (int (*) (int, FILE *)) dlsym_rtld_next( "fputc" );
		libc_fputs = (int (*) (const char *, FILE *)) dlsym_rtld_next( "fputs" );
		libc_read = (ssize_t (*) (int , void *, size_t)) dlsym_rtld_next( "read" );
		libc_write = (ssize_t (*) (int , const void *, size_t)) dlsym_rtld_next( "write" );
		libc_fwrite = (size_t (*) (const void *, size_t, size_t, FILE *)) dlsym_rtld_next( "fwrite" );
		libc_exit = (void (*) (int)) dlsym_rtld_next( "exit" );
		libc__exit = (void (*) (int)) dlsym_rtld_next( "_exit" );
	}

	pthread_mutex_unlock( &g_mutex );
}

// ==================================================

void __print_all_parent_cmd ( FILE *fout, pid_t pid_start, pid_t pid_end )
{
	while ( (pid_start != pid_end) && (pid_start != 1) )
	{
		
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
			libc_exit(1);
		}
		strcpy( buf, file_name );
	}
}

void __get_proc_exec_name ( char *buf, pid_t pid )
{
	char exec_link_path[BUFSIZ] = {0};
	libc_sprintf( exec_link_path, "/proc/%d/cmdline", pid );
	FILE *fin = fopen_w_check( exec_link_path, "r" );
	if ( fin )
	{
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
					fclose( fin );
					return;
				}
				i += j + 1;
			}

			strcpy( buf, shell );
			fclose( fin );
			return;
		}

		fclose( fin );
		strcpy( buf, arg );
	}
	else
	{
		strcpy( buf, "N/A" );
	}
}

void __get_proc_cmd ( char *cmd_buf, pid_t pid )
{
	char exec_link_path[BUFSIZ] = {0};
	libc_sprintf( exec_link_path, "/proc/%d/cmdline", pid );
	FILE *fin = fopen_w_check( exec_link_path, "r" );
	if ( fin )
	{
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
	else
	{
		strcpy( cmd_buf, "N/A" );
	}
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
	__link_libc_functions();

	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/exit.report", g_output_dir );
	FILE *fout = fopen_w_check( report_file, "a" );
	if ( fout )
	{
		char cmd[BUFSIZ];
		pid_t pid = syscall(SYS_getpid);
		pid_t ppid = syscall(SYS_getppid);
		__get_proc_cmd( cmd, pid );
		libc_fprintf( fout, "exit=%d pid=%d ppid=%d cmd=%s\n", exit_code, pid, ppid, cmd );
		fclose( fout );
	}

	libc_exit( exit_code );
	__asm__( "hlt" ); // prevent exit fail
}

void _exit ( int exit_code ) 
{
	__link_libc_functions();

	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/exit.report", g_output_dir );
	FILE *fout = fopen_w_check( report_file, "a" );
	if ( fout )
	{
		char cmd[BUFSIZ];
		pid_t pid = syscall(SYS_getpid);
		__get_proc_cmd( cmd, pid );
		libc_fprintf( fout, "_exit=%d pid=%d cmd=%s\n", exit_code, pid, cmd );
		fclose( fout );
	}

	libc__exit( exit_code );
	__asm__( "hlt" );
}
