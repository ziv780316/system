#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include <stdarg.h>

#include "misc.h"

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_dump_type = DUMP_NONE;
static char *g_output_dir = NULL;
static pid_t g_io_monitor_pid = -1;
static int g_io_monitor_shm_id;
unsigned int *g_ipc_monitor_flag = NULL;

ssize_t (*libc_read) (int , void *, size_t) = NULL;
ssize_t (*libc_write) (int , const void *, size_t) = NULL;
size_t (*libc_fwrite) (const void *, size_t, size_t, FILE *) = NULL;
size_t (*libc_fread) (const void *, size_t, size_t, FILE *) = NULL;
int (*libc_fflush) (FILE *) = NULL;
int (*libc_fputc) (int, FILE *) = NULL;
int (*libc_fputs) (const char *, FILE *) = NULL;
int (*libc_printf) (const char*, ...) = NULL;
int (*libc_fprintf) (FILE *, const char*, ...) = NULL;
int (*libc_sprintf) (char *, const char*, ...) = NULL;
int (*libc_vprintf) (const char*, va_list) = NULL;
int (*libc_vsprintf) (char *, const char*, va_list) = NULL;
int (*libc_vfprintf) (FILE *, const char*, va_list) = NULL;
int (*libc_fscanf) (FILE *, const char *, ...) = NULL;
int (*libc_sscanf) (const char *, const char *, ...) = NULL;
char (*libc_fgets) (char *, int, FILE *) = NULL;
pid_t (*libc_fork) () = NULL;
pid_t (*libc_vfork) () = NULL;
int (*libc_execle) (const char *, const char *, ...) = NULL;
void (*libc_exit) (int) = NULL;
void (*libc__exit) (int) = NULL;
int (*libc_unlink) (const char *) = NULL;
int (*libc_remove) (const char *) = NULL;

static void create_dir ( char *dir )
{
	if( (-1 == mkdir( dir, S_IRWXU )) && (EEXIST != errno) )
	{
		fprintf( stderr, "[Error] create directory \"%s\" fail -> %s\n", dir, strerror(errno) );
		exit(1);
	}
}

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

static void *dynamic_array_realloc( void *mem, size_t origin_n_memb, size_t new_n_memb, size_t memb_size )
{
	const bool debug = false;

	const size_t growth_rate = 2;

	// find power of growth_rate
	size_t val;
	size_t origin_bound = 1;
	val = origin_n_memb;
	do
	{
		val /= growth_rate;
		origin_bound *= growth_rate;
	} while ( val > 0 );

	size_t new_bound = 1;
	val = new_n_memb;
	do
	{
		val /= growth_rate;
		new_bound *= growth_rate;
	} while ( val > 0 );

	// allocate
	// amortize algorithm, each call of dynamic_array_realloc is comsume O(1)
	// pf:
	// N dynamic_array_realloc call and new_n_memb from 1 ~ n
	// 1 + 2 + 4 + 8 + ... + 2^(log2(new_n_memb) + 1) < 2 * new_n_memb
	// amortized each call consume only (2 * new_n_memb)/N is O(1)
	if ( 0 == origin_n_memb )
	{
		mem = (void *) malloc( new_bound * memb_size );
		if ( debug )
		{
			fprintf( stderr, "[Dynamic Array] growth space 0 -> %lu\n", new_bound );
		}
	}
	else if ( origin_bound < new_bound )
	{
		if ( debug )
		{
			fprintf( stderr, "[Dynamic Array] growth space %lu -> %lu\n", origin_bound, new_bound );
		}
		mem = (void *) realloc( mem, (new_bound * memb_size) );
	}
	else
	{
		// there are remain spice, nothing to do
	}

	return mem;
}

sighandler_t register_signal_handler ( int signum, void (*fp) (int) )
{
	struct sigaction new_action, old_action;
	new_action.sa_handler = fp;
	sigemptyset( &new_action.sa_mask );
	new_action.sa_flags = 0;
	if ( -1 == sigaction( signum, NULL, &old_action ) )
	{
		fprintf( stderr, "[Error] sigaction get old action fail -> %s\n", strerror(errno) );
		exit(1);
	}
	if ( -1 == sigaction( signum, &new_action, NULL ) )
	{
		fprintf( stderr, "[Error] sigaction register fail -> %s\n", strerror(errno) );
		exit(1);
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

static char *getenv_thread_save ( char **env, const char *name )
{
	if ( (NULL == env) || ('\0' == name[0]) )
	{
		return NULL;
	}

	int name_len = 0;
	for ( int i = 0; name[i]; ++i )
	{
		++name_len;
	}

	char *ep;
	for ( int i = 0; env[i]; ++i )
	{
		ep = env[i];

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

	if ( 0 == (pid = libc_fork()) )
	{
		close( fd[0] );
		if( -1 == dup2( fd[1], STDOUT_FILENO ) )
		{
			libc_fprintf( stderr, "[Error] dup2 fail -> %s\n", strerror(errno) );
			libc_exit(1);
		}

		// child execute with sh has patter expasion (i.e. *)
		libc_execle( "/bin/sh", "sh", "-c", (const char *)cmd, (char *) NULL, (char *) NULL );

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

static void print_backtrace_pstree ( pid_t pid )
{
	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/pstree.%d", g_output_dir, pid );
	FILE *fout = fopen_w_check( report_file, "w" );

	char proc_file[BUFSIZ];
	pid_t current_pid = pid;
	pid_t ppid;
	int scanf_result;
	char *ret;
	char exec_cmd[BUFSIZ];
	char *exec_result;
	char line[BUFSIZ];
	FILE *fin;
	while ( true )
	{
		libc_sprintf( proc_file, "/proc/%d/status", current_pid );
		fin = fopen_w_check( proc_file, "r" );
		if ( fin )
		{
			while ( true )
			{
				ret = fgets( line, BUFSIZ, fin );
				if ( ret )
				{
					scanf_result = libc_sscanf( line, "PPid: %d", &ppid );
					if ( scanf_result > 0 )
					{
						// match
						break;
					}
				}
				else
				{
					// error or EOF
					libc_fprintf( stderr, "[Error] cannot find PPid in %s\n", proc_file );
					fclose( fin );
					goto end_print_backtrace_pstree;
				}
			}

			fclose( fin );
		}
		else
		{
			break;
		}
		
		libc_sprintf( exec_cmd, "cat /proc/%d/cmdline | tr '\\0' ' '", current_pid );
		run_shell_command_and_get_results( &exec_result, exec_cmd );
		libc_fprintf( fout, "pid=%d cmd=%s\n", current_pid, exec_result );
		free( exec_result );
		current_pid = ppid;

		if ( (1 == current_pid) || (g_io_monitor_pid == current_pid) )
		{
			libc_sprintf( exec_cmd, "cat /proc/%d/cmdline | tr '\\0' ' '", current_pid );
			run_shell_command_and_get_results( &exec_result, exec_cmd );
			libc_fprintf( fout, "pid=%d cmd=%s\n", current_pid, exec_result );
			free( exec_result );
			break;
		}
	}

end_print_backtrace_pstree:

	fclose( fout );
}

static void run_shell_command ( const char *cmd )
{
	int status;
	pid_t pid;
	if ( 0 == (pid = libc_fork()) )
	{
		// child execute with sh has patter expasion (i.e. *)
		libc_execle( "/bin/sh", "sh", "-c", (const char *)cmd, (char *) NULL, (char *) NULL );

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
	pid = getpid();
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
	libc_sscanf = (int (*) (const char *, const char *, ...)) dlsym_rtld_next( "sscanf" );
	libc_fgets = (char (*) (char *, int, FILE *)) dlsym_rtld_next( "fgets" );
	libc_fork = (pid_t (*) ()) dlsym_rtld_next ( "fork" );
	libc_execle = (int (*) (const char *, const char *, ...)) dlsym_rtld_next ( "execle" );

	// record pid and command
	pid_t pid = getpid();
	pid_t ppid = getppid();
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
		print_backtrace_pstree( pid );
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
	env = getenv_thread_save( __environ, "IO_MONITOR_SHM_ID" );
	if ( env )
	{
		g_io_monitor_shm_id = atoi( env );
	}

	env = getenv_thread_save( __environ, "IO_MONITOR_DUMP_TYPE" );
	if ( !env )
	{
		g_dump_type = DUMP_ASCII;
	}
	else
	{
		g_dump_type = atoi( env );
	}

	env = getenv_thread_save( __environ, "IO_MONITOR_REPORT_DIR" );
	if ( !env )
	{
		g_output_dir = strdup( "/tmp" );
	}
	else
	{
		g_output_dir = strdup( env );
	}

	env = getenv_thread_save( __environ, "IO_MONITOR_PID" );
	if ( env )
	{
		g_io_monitor_pid = atoi( env );
	}

	// get real time control share memory
	if ( -1 == g_io_monitor_pid )
	{
		// unit test flow
		g_ipc_monitor_flag = (unsigned int *) malloc ( sizeof(unsigned int) );
		*g_ipc_monitor_flag = IO_MONITOR_IPC_MONITOR_ALL;
	}
	else
	{
		g_ipc_monitor_flag = (unsigned int *) shmat( g_io_monitor_shm_id, NULL, 0 );
		if ( !g_ipc_monitor_flag )
		{
			libc_fprintf( stderr, "[Error] shmat get data fail -> %s\n", strerror(errno) );
			exit(1);
		}
	}

	// register signal 
	register_signal_handler( SIGSEGV, sigsegv_backtrace );
	register_signal_handler( SIGCHLD, SIG_DFL ); // prevent fork parent miss child exit sigchld

	__record_process_info();
}

void __sync_ipc ()
{
	while( *g_ipc_monitor_flag == IO_MONITOR_IPC_MONITOR_STOP )
	{
		usleep( 100000 );
	}
}

void __link_libc_functions ()
{
	pthread_mutex_lock( &g_mutex );

	static bool initialized = false;
	if ( !initialized )
	{
		initialized = true;

		__init_monitor();

		// bind origin libc function
		libc_fprintf = (int (*) (FILE *, const char *, ...)) dlsym_rtld_next( "fprintf" );
		libc_printf = (int (*) (const char *, ...)) dlsym_rtld_next( "printf" );
		libc_sprintf = (int (*) (char *, const char *, ...)) dlsym_rtld_next( "sprintf" );
		libc_vfprintf = (int (*) (FILE *, const char *, va_list)) dlsym_rtld_next( "vfprintf" );
		libc_vprintf = (int (*) (const char *, va_list)) dlsym_rtld_next( "vprintf" );
		libc_vsprintf = (int (*) (char *, const char *, va_list)) dlsym_rtld_next( "vsprintf" );
		libc_fscanf = (int (*) (FILE *, const char *, ...)) dlsym_rtld_next( "fscanf" );
		libc_sscanf = (int (*) (const char *, const char *, ...)) dlsym_rtld_next( "sscanf" );
		libc_fgets = (char (*) (char *, int, FILE *)) dlsym_rtld_next( "fgets" );
		libc_fflush = (int (*) (FILE *)) dlsym_rtld_next( "fflush" );
		libc_fputc = (int (*) (int, FILE *)) dlsym_rtld_next( "fputc" );
		libc_fputs = (int (*) (const char *, FILE *)) dlsym_rtld_next( "fputs" );
		libc_read = (ssize_t (*) (int , void *, size_t)) dlsym_rtld_next( "read" );
		libc_write = (ssize_t (*) (int , const void *, size_t)) dlsym_rtld_next( "write" );
		libc_fwrite = (size_t (*) (const void *, size_t, size_t, FILE *)) dlsym_rtld_next( "fwrite" );
		libc_fread = (size_t (*) (const void *, size_t, size_t, FILE *)) dlsym_rtld_next( "fread" );
		libc_fork = (pid_t (*) ()) dlsym_rtld_next ( "fork" );
		libc_execle = (int (*) (const char *, const char *, ...)) dlsym_rtld_next ( "execle" );
		libc_exit = (void (*) (int)) dlsym_rtld_next( "exit" );
		libc__exit = (void (*) (int)) dlsym_rtld_next( "_exit" );
		libc_unlink = (int (*) (const char *)) dlsym_rtld_next( "unlink" );
		libc_remove = (int (*) (const char *)) dlsym_rtld_next( "remove" );
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
		pid_t pid = getpid();
		pid_t ppid = getppid();
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
		pid_t pid = getpid();
		__get_proc_cmd( cmd, pid );
		libc_fprintf( fout, "_exit=%d pid=%d cmd=%s\n", exit_code, pid, cmd );
		fclose( fout );
	}

	libc__exit( exit_code );
	__asm__( "hlt" );
}

pid_t fork ()
{
	__link_libc_functions();

	pid_t fork_pid = libc_fork();
	if ( 0 == fork_pid )
	{
		pid_t pid = getpid();
		pid_t ppid = getppid();
		char report_file[BUFSIZ];
		libc_sprintf( report_file, "%s/init.report", g_output_dir );
		FILE *fout = fopen_w_check( report_file, "a" );
		if ( fout )
		{
			libc_fprintf( fout, "pid=%d fork child_pid=%d\n", ppid, pid );
			fclose( fout );
		}
	}
	return fork_pid;
}

pid_t vfork ()
{
	__link_libc_functions();

	pid_t fork_pid = libc_fork();
	if ( 0 == fork_pid )
	{
		pid_t pid = getpid();
		pid_t ppid = getppid();
		char report_file[BUFSIZ];
		libc_sprintf( report_file, "%s/init.report", g_output_dir );
		FILE *fout = fopen_w_check( report_file, "a" );
		if ( fout )
		{
			libc_fprintf( fout, "pid=%d vfork child_pid=%d\n", ppid, pid );
			fclose( fout );
		}
	}
	return fork_pid;
}

int execle ( const char *path, const char *arg0, ... )
{
	int argc = 0;
	int envc = 0;
	char *arg;
	char **argv;
	char **env;

	argv = (char **) dynamic_array_realloc( argv, argc, argc + 1, sizeof(char *) );
	argv[argc] = strdup( arg0 );
	++argc;

	// extract argv 
	va_list va;
	va_start( va, arg0 );
	arg = va_arg( va, char * );
	while ( NULL != arg )
	{
		argv = (char **) dynamic_array_realloc( argv, argc, argc + 1, sizeof(char *) );
		argv[argc] = strdup( arg );
		++argc;
		arg = va_arg( va, char * );
	}
	argv = (char **) dynamic_array_realloc( argv, argc, argc + 1, sizeof(char *) );
	argv[argc] = NULL;

	// extract env
	env = va_arg( va, char ** );
	va_end( va );
	if ( NULL == env )
	{
		// envc is 0
	}
	else
	{
		for ( int i = 0; NULL != env[i]; ++i )
		{
			++envc;
		}
	}

	// export necessary env
	if( NULL == getenv_thread_save( env, "LD_PRELOAD" ) )
	{
		char report_file[BUFSIZ];
		libc_sprintf( report_file, "%s/init.report", g_output_dir );
		FILE *fout = fopen_w_check( report_file, "a" );
		libc_fprintf( fout, "pid=%d call execle w/o LD_PRELOAD, set LD_PRELOAD=%s\n", getpid(), getenv_thread_save( __environ, "LD_PRELOAD") );
		libc_fprintf( fout, " + argc=%d\n", argc );
		libc_fprintf( fout, " + envc=%d\n", envc );
		for ( int i = 0; i < argc; ++i )
		{
			libc_fprintf( fout, " + argv[%d]=%s\n", i, argv[i] );
		}

		// export LD_PRELOAD
		char envbuf[BUFSIZ];
		libc_sprintf( envbuf, "LD_PRELOAD=%s", getenv_thread_save( __environ, "LD_PRELOAD" ) );
		env = (char **) realloc( env, (envc + 2) * sizeof(char *) ); // LD_PRELOAD + NULL
		env[envc] = strdup( envbuf );
		env[envc + 1] = NULL;
		++envc;

		if ( getenv_thread_save( __environ, "IO_MONITOR_SHM_ID") && (NULL == getenv_thread_save( env, "IO_MONITOR_SHM_ID")) )
		{
			libc_sprintf( envbuf, "IO_MONITOR_SHM_ID=%s", getenv_thread_save( __environ, "IO_MONITOR_SHM_ID" ) );
			env = (char **) realloc( env, (envc + 2) * sizeof(char *) ); 
			env[envc] = strdup( envbuf );
			env[envc + 1] = NULL;
			++envc;
		}
		if ( getenv_thread_save( __environ, "IO_MONITOR_DUMP_TYPE") && (NULL == getenv_thread_save( env, "IO_MONITOR_DUMP_TYPE")) )
		{
			libc_sprintf( envbuf, "IO_MONITOR_DUMP_TYPE=%s", getenv_thread_save( __environ, "IO_MONITOR_DUMP_TYPE" ) );
			env = (char **) realloc( env, (envc + 2) * sizeof(char *) ); 
			env[envc] = strdup( envbuf );
			env[envc + 1] = NULL;
			++envc;
		}
		if ( getenv_thread_save( __environ, "IO_MONITOR_REPORT_DIR") && (NULL == getenv_thread_save( env, "IO_MONITOR_REPORT_DIR")) )
		{
			libc_sprintf( envbuf, "IO_MONITOR_REPORT_DIR=%s", getenv_thread_save( __environ, "IO_MONITOR_REPORT_DIR" ) );
			env = (char **) realloc( env, (envc + 2) * sizeof(char *) ); 
			env[envc] = strdup( envbuf );
			env[envc + 1] = NULL;
			++envc;
		}

		for ( int i = 0; i < envc; ++i )
		{
			libc_fprintf( fout, " + env[%d]=%s\n", i, env[i] );
		}

		fclose( fout );
	}

	int status = execve( path, (char **const)argv, (char **const)env );

	for ( int i = 0; i < argc; ++i )
	{
		free( argv[i] );
	}

	return status;
}

int unlink ( const char *path )
{
	__link_libc_functions();

	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/remove.report", g_output_dir );
	FILE *fout = fopen_w_check( report_file, "a" );
	if ( fout )
	{
		pid_t pid = getpid();
		pid_t ppid = getppid();
		char cmd[BUFSIZ];
		__get_proc_cmd( cmd, pid );
		libc_fprintf( fout, "pid=%d ppid=%d unlink=%s cmd=%s\n", pid, ppid, path, cmd );

		char *exec_result;
		char exec_cmd[BUFSIZ];
		libc_sprintf( exec_cmd, "cp %s %s/remove.%s 2>&1", path, g_output_dir, basename(path) );
		run_shell_command_and_get_results( &exec_result, exec_cmd );
		if ( strlen(exec_result) > 0 )
		{
			// cp fail
			libc_fprintf( fout, "cp %s fail -> %s\n", path, exec_result );
		}
		free( exec_result );

		fclose( fout );
	}

	return libc_unlink( path );
}

int remove ( const char *path )
{
	__link_libc_functions();

	char report_file[BUFSIZ];
	libc_sprintf( report_file, "%s/remove.report", g_output_dir );
	FILE *fout = fopen_w_check( report_file, "a" );
	if ( fout )
	{
		pid_t pid = getpid();
		pid_t ppid = getppid();
		char cmd[BUFSIZ];
		__get_proc_cmd( cmd, pid );
		libc_fprintf( fout, "pid=%d ppid=%d remove=%s cmd=%s\n", pid, ppid, path, cmd );

		char *exec_result;
		char exec_cmd[BUFSIZ];
		libc_sprintf( exec_cmd, "cp %s %s/remove.%s 2>&1", path, g_output_dir, basename(path) );
		run_shell_command_and_get_results( &exec_result, exec_cmd );
		if ( strlen(exec_result) > 0 )
		{
			// cp fail
			libc_fprintf( fout, "cp %s fail -> %s\n", path, exec_result );
		}
		free( exec_result );

		fclose( fout );
	}

	return libc_remove( path );
}
