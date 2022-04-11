#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <execinfo.h>
#include <sys/shm.h>

#include "io_monitor.h"
#include "opts.h"

// store pre-compile .so
#include "libio_read.hex" 
#include "libio_write.hex" 
#include "libio_both.hex" 
#include "replace_functions"

monitor_t g_monitor;

// ==================================================
// atexit works
// ==================================================

void remove_tmp_so ()
{
	remove( g_monitor.tmp_so_name );
}

void remove_shm ()
{
	// can use ipcs -m to check remove or not
	if ( -1 == shmdt( g_monitor.ipc_monitor_flag ) )
	{
		fprintf( stderr, "[Warning] shmdt detach share memory id=%d fail -> %s\n", g_monitor.shm_id, strerror(errno) );
	}

	
	if ( -1 == shmctl( g_monitor.shm_id, IPC_RMID, 0 ) )
	{
		fprintf( stderr, "[Warning] shmctl remove share memory id=%d fail -> %s\n", g_monitor.shm_id, strerror(errno) );
	}
}

void kill_monitored_process ()
{
	if ( -1 == kill( g_monitor.child_pid, SIGTERM ) )
	{
		if ( ESRCH != errno )
		{
			fprintf( stderr, "[Warning] kill child pid=%d fail -> %s\n", g_monitor.child_pid, strerror(errno) );
		}
	}
}

void register_monitor_atext_works ()
{
	atexit( remove_tmp_so );
	atexit( remove_shm );
	atexit( kill_monitored_process );
}

// ==================================================
// signal handler
// ==================================================
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

void io_monitor_sigchild ( int signum )
{
	printf( "Child pid=%d terminated\n", g_monitor.child_pid );
	exit(0); // call atexit flow
}

void register_monitor_signal_handlers()
{
	register_signal_handler( SIGCHLD, io_monitor_sigchild ); // child terminated
	register_signal_handler( SIGINT, exit ); 
}

void signal_do_nothing ( int signum )
{
}

// ==================================================

// ==================================================
// monitor works
// ==================================================
void create_tmp_so_file ( int *tmpfile_fd, char **ptmpfile_name )
{
	char *tmpfile_name = (char *) calloc( BUFSIZ, sizeof(char) );
	sprintf( tmpfile_name, "/tmp/.lib.so.XXXXXX" );
	int fd = mkstemp( tmpfile_name );
	if ( -1 == fd )
	{
		fprintf( stderr, "[error] create tmpfile name fail -> %s\n", strerror(errno) );
		exit(1);
	}
	*ptmpfile_name = strdup( tmpfile_name ); 
	*tmpfile_fd = fd;
}

void resolve_path_name ( char **path )
{
	// change to abs path
	char *resolved_path = NULL;
	char *buf = realpath( *path, resolved_path );
	if ( NULL == resolved_path )
	{
		if ( NULL == buf )
		{
			fprintf( stderr, "[Error] cannot resolve path %s -> %s\n", *path, strerror(errno) );
			exit(1);
		}
		else
		{
			// resolved path length > PATH_MAX
			*path = buf;
		}
	}
	else
	{
		free( *path );
		*path = strdup( resolved_path );
	}

}

void dump_pre_compile_lib ()
{
	int n_write;
	if ( MONITOR_READ == g_monitor.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd, libio_read_so, libio_read_so_len );
		if ( n_write != libio_read_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_read_so_len=%d, dump libio_read.so to %s (fd=%d) fail -> %s\n", n_write, libio_read_so_len, g_monitor.tmp_so_name, g_monitor.tmpfile_fd, strerror(errno) );
			exit(1);
		}
	}
	else if ( MONITOR_WRITE == g_monitor.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd, libio_write_so, libio_write_so_len );
		if ( n_write != libio_write_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_write_so_len=%d, dump libio_write.so to %s (fd=%d) fail -> %s\n", n_write, libio_write_so_len, g_monitor.tmp_so_name, g_monitor.tmpfile_fd, strerror(errno) );
			exit(1);
		}
	}
	else if ( MONITOR_BOTH == g_monitor.monitor_type )
	{
		n_write = write( g_monitor.tmpfile_fd, libio_both_so, libio_both_so_len );
		if ( n_write != libio_both_so_len )
		{
			fprintf( stderr, "[Error] n_write=%d != libio_both_so_len=%d, dump libio_both.so to %s (fd=%d) fail -> %s\n", n_write, libio_both_so_len, g_monitor.tmp_so_name, g_monitor.tmpfile_fd, strerror(errno) );
			exit(1);
		}
	}
}

void create_ipc_shm ()
{
	int total_len = 0;
	int cnt = 0;
	int shm_size = 0;
	int incr;
	int len;
	const char *name;
	char *func_list = NULL;
	while( (name = replace_functions[cnt]) != NULL )
	{
		len = strlen(name);
		incr = len + 1; // include '\0' 
		total_len += incr;
		func_list = (char *) realloc ( func_list, total_len );
		sprintf( func_list + total_len - incr, "%s", name );
		++cnt;
	}

	shm_size = sizeof(unsigned int); // ipc_monitor_flag;
	shm_size += sizeof(unsigned int) + sizeof(int) + total_len + (cnt * sizeof(bool)); 
	g_monitor.shm_size = shm_size;
	g_monitor.n_monitor_function = cnt;

	key_t key;
	key = ftok( g_monitor.tmp_so_name, IO_MONITOR_IPC_PROJ_ID );
	if ( -1 == key )
	{
		fprintf( stderr, "[Error] ftok generate IPC key fail (path=%s) -> %s\n", g_monitor.tmp_so_name, strerror(errno) );
		exit(1);
	}

	int shm_id;
	shm_id = shmget( key, g_monitor.shm_size, 0644 | IPC_CREAT );
	if ( -1 == shm_id )
	{
		fprintf( stderr, "[Error] shmget share memory create fail -> %s\n", strerror(errno) );
		exit(1);
	}
	g_monitor.shm_id = shm_id;

	char *base = (char *)shmat( shm_id, NULL, 0 );
	if ( !base )
	{
		fprintf( stderr, "[Error] shmat get data fail -> %s\n", strerror(errno) );
		exit(1);
	}

	// init ipc_monitor_flag
	g_monitor.ipc_monitor_flag = (unsigned int *) base;
	*(g_monitor.ipc_monitor_flag) = IO_MONITOR_IPC_MONITOR_STOP;

	// init n_monitor_function
	g_monitor.n_monitor_function = cnt;
	*(int *)(base + sizeof(unsigned int)) = g_monitor.n_monitor_function;

	// init ipc_monitor_functions
	g_monitor.ipc_monitor_functions = (base + sizeof(unsigned int) + sizeof(int));
	char *dest_ptr = g_monitor.ipc_monitor_functions;
	char *src_ptr = func_list;
	for ( int i = 0; i < cnt; ++i )
	{
		len = strlen(src_ptr);
		strcpy(dest_ptr, src_ptr);
		*(bool *)(dest_ptr + len + 1) = true;
		dest_ptr += len + 1 + 1; // + '\0' + bool
		src_ptr += strlen(src_ptr) + 1;
	}
}

void set_ld_preload_lib ()
{
	if ( -1 == setenv( "LD_PRELOAD", g_monitor.tmp_so_name, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"LD_PRELOAD\" fail -> %s\n", strerror(errno) );
		exit(1);
	}
}

void set_options_in_env ()
{
	char buf[BUFSIZ];
	sprintf( buf, "%d", g_monitor.dump_type );
	if ( -1 == setenv( "IO_MONITOR_DUMP_TYPE", buf, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"IO_MONITOR_DUMP_TYPE\" fail -> %s\n", strerror(errno) );
		exit(1);
	}
	sprintf( buf, "%s", g_monitor.result_dir );
	if ( -1 == setenv( "IO_MONITOR_REPORT_DIR", buf, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"IO_MONITOR_REPORT_DIR\" fail -> %s\n", strerror(errno) );
		exit(1);
	}
	sprintf( buf, "%d", getppid() );
	if ( -1 == setenv( "IO_MONITOR_PID", buf, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"IO_MONITOR_PID\" fail -> %s\n", strerror(errno) );
		exit(1);
	}
	sprintf( buf, "%d", g_monitor.shm_id );
	if ( -1 == setenv( "IO_MONITOR_SHM_ID", buf, 1 ) ) // overwrite
	{
		fprintf( stderr, "[Error] setenv \"IO_MONITOR_SHM_ID\" fail -> %s\n", strerror(errno) );
		exit(1);
	}
}

void create_dir ( char *dir )
{
	if( (-1 == mkdir( dir, S_IRWXU )) && (EEXIST != errno) )
	{
		fprintf( stderr, "[Error] create directory \"%s\" fail -> %s\n", dir, strerror(errno) );
		exit(1);
	}
}

void show_monitor_functions ()
{
	char *ptr = g_monitor.ipc_monitor_functions;
	int n_monitor_function = g_monitor.n_monitor_function;
	int len;
	printf( " + monitor functions:" );
	for ( int i = 0; i < n_monitor_function; ++i )
	{
		len = strlen(ptr);
		if ( true == *(bool *)(ptr + len + 1) )
		{
			printf( " %s", ptr );
		}
		ptr += len + 1 + 1; // skip '\0' and bool
	}
	printf( "\n" );
}

void unregister_monitor_functions ( const char *func )
{
	char *ptr = g_monitor.ipc_monitor_functions;
	int n_monitor_function = g_monitor.n_monitor_function;
	int len;
	for ( int i = 0; i < n_monitor_function; ++i )
	{
		len = strlen(ptr);
		if ( true == *(bool *)(ptr + len + 1) )
		{
			if ( 0 == strcmp(ptr, func) )
			{
				*(bool *)(ptr + len + 1) = false;
				return;
			}
		}
		ptr += len + 1 + 1; // skip '\0' and bool
	}
	printf( "[Warning] function %s is not in monitor list\n", func );
}

void io_monitor_user_interaction ()
{
	int cnt = 0;
	char current_key[BUFSIZ] = {0};
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_STOP )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_STOP;
	}
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_OFF )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_OFF;
	}
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_READ )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_READ;
	}
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_WRITE )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_WRITE;
	}
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_PSTREE )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_PSTREE;
	}
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_ENV )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_ENV;
	}
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_REMOVE )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_REMOVE;
	}
	if ( *(g_monitor.ipc_monitor_flag) & IO_MONITOR_IPC_MONITOR_FILE )
	{
		current_key[cnt++] = IO_MONITOR_USER_KEY_MONITOR_FILE;
	}

	char user_key[BUFSIZ];
	printf( "* stop(s) off(o) continue(c) file(f) read(r) write(w) pstree(p) env(e) remove(m) all(a) kill(k) unregister(u)\n" );
	printf( " + input monitor command (current=%s): ", current_key );
	scanf( "%s", user_key );

	int key;
	for ( int i = 0; user_key[i]; ++i )
	{
		key = user_key[i];
		switch ( key )
		{
			case IO_MONITOR_USER_KEY_MONITOR_CONTINUE:
				*(g_monitor.ipc_monitor_flag) &= ~IO_MONITOR_IPC_MONITOR_STOP;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_STOP:
				*(g_monitor.ipc_monitor_flag) = IO_MONITOR_IPC_MONITOR_STOP;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_OFF:
				*(g_monitor.ipc_monitor_flag) = IO_MONITOR_IPC_MONITOR_OFF;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_READ:
				*(g_monitor.ipc_monitor_flag) |= IO_MONITOR_IPC_MONITOR_READ;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_WRITE:
				*(g_monitor.ipc_monitor_flag) |= IO_MONITOR_IPC_MONITOR_WRITE;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_PSTREE:
				*(g_monitor.ipc_monitor_flag) |= IO_MONITOR_IPC_MONITOR_PSTREE;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_ENV:
				*(g_monitor.ipc_monitor_flag) |= IO_MONITOR_IPC_MONITOR_ENV;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_REMOVE:
				*(g_monitor.ipc_monitor_flag) |= IO_MONITOR_IPC_MONITOR_REMOVE;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_FILE:
				*(g_monitor.ipc_monitor_flag) |= IO_MONITOR_IPC_MONITOR_FILE;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_ALL:
				*(g_monitor.ipc_monitor_flag) = IO_MONITOR_IPC_MONITOR_ALL;
				break;

			case IO_MONITOR_USER_KEY_MONITOR_UNREGISTER:
				{
					char buf[BUFSIZ];
					printf( " + enter unregister function: " );
					if ( 1 == scanf("%s", buf) )
					{
						unregister_monitor_functions( buf );
						show_monitor_functions();
					}
				}
				break;

			case IO_MONITOR_USER_KEY_MONITOR_KILL:
				exit(0);
				break;

			default: 
				fprintf( stderr, "[Warning] unknown monitor key %c\n", key );
		}
	}
}

// ==================================================

int main ( int argc, char **argv )
{
	setbuf( stdout, 0 ); // prevent fork fflush twice

	if ( 1 == argc )
	{
		show_help();
	}
	else
	{
		// getopt parse command line arguments
		parse_cmd_options ( argc, argv );

		// tmp file is preload .so
		create_tmp_so_file( &(g_monitor.tmpfile_fd), &(g_monitor.tmp_so_name) );

		// dump .so
		dump_pre_compile_lib();

		// create directory to collect report
		create_dir( g_monitor.result_dir );
		resolve_path_name( &(g_monitor.result_dir) );

		// create share memory for IPC
		create_ipc_shm();

		// get user setting
		int status;
		pid_t pid;
		if ( 0 == (pid = fork()) )
		{
			// polling wait parent 
			while ( IO_MONITOR_IPC_MONITOR_STOP == *(g_monitor.ipc_monitor_flag) )
			{
				usleep(10000);
			}

			// set LD_PRELOAD
			set_ld_preload_lib();

			// send dump type and report dir to child
			set_options_in_env();
			
			// child execute with sh has patter expasion (i.e. *)
			printf( "\n* Child stdout:\n" );
			printf( "--------------------------\n" );
			execlp( "/bin/sh", "sh", "-c", (const char *)g_monitor.cmd, (char *) NULL );

			// exec return only in fail
			fprintf( stderr, "[Error] exec fail -> %s\n", strerror(errno) );
			exit(1);
		}
		else
		{
			// parent
			g_monitor.child_pid = pid;

			// exit and signal handler
			register_monitor_atext_works();
			register_monitor_signal_handlers();

			printf( "* Monitor information:\n" );
			printf( "--------------------------\n" );
			printf( "monitor cmd  = %s\n", g_monitor.cmd );
			printf( "tmp so path  = %s\n", g_monitor.tmp_so_name );
			printf( "report dir   = %s\n", g_monitor.result_dir );
			printf( "child pid    = %d\n", g_monitor.child_pid );
			printf( "shm ID       = %d\n", g_monitor.shm_id );
			printf( "shm size     = %d\n", g_monitor.shm_size );
			printf( "n_monitor    = %d\n", g_monitor.n_monitor_function );
			printf( "monitor functions =" );
			for ( int i = 0; i < g_monitor.n_monitor_function; ++i )
			{
				printf( " %s", replace_functions[i] );
			}
			printf( "\n" );

			if ( g_opts.interactive_mode )
			{
				printf( "\n--------------------------\n" );
				printf( "* enter the first monitor flag\n" );
				while( true )
				{
					io_monitor_user_interaction();
				}
			}
			else
			{
				*(g_monitor.ipc_monitor_flag) = IO_MONITOR_IPC_MONITOR_READ | IO_MONITOR_IPC_MONITOR_WRITE | IO_MONITOR_IPC_MONITOR_REMOVE | IO_MONITOR_USER_KEY_MONITOR_FILE;
				if ( -1 != waitpid( g_monitor.child_pid, &status, 0 ) )
				{
					printf( "Child pid=%d terminated with status=%d\n", g_monitor.child_pid, status );
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

