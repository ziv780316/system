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
#include <fcntl.h>
#include <signal.h>
#include <execinfo.h>
#include <gnu/libc-version.h>
#include <sys/shm.h>

#include "io_monitor.h"
#include "opts.h"

// store pre-compile .so
#include "libio_read.hex" 
#include "libio_write.hex" 
#include "libio_both.hex" 

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
	exit(0);
}

void register_monitor_signal_handlers()
{
	register_signal_handler( SIGCHLD, io_monitor_sigchild ); // child terminated
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
	sprintf( tmpfile_name, "/tmp/.libXXXXXX" );
	mkstemp( tmpfile_name );
	if ( NULL == tmpfile_name )
	{
		fprintf( stderr, "[error] create tmpfile name fail -> %s\n", strerror(errno) );
		exit(1);
	}
	char so_name[BUFSIZ];
	sprintf( so_name, "%s.so", tmpfile_name );

	int fd = open( so_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU );
	if ( -1 == fd )
	{
		fprintf( stderr, "[error] create tmpfile %s fail -> %s\n", so_name, strerror(errno) );
		exit(1);
	}

	*ptmpfile_name = strdup( so_name );
	*tmpfile_fd = fd;
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
	key_t key;
	key = ftok( g_monitor.tmp_so_name, IO_MONITOR_IPC_PROJ_ID );
	if ( -1 == key )
	{
		fprintf( stderr, "[Error] ftok generate IPC key fail -> %s\n", strerror(errno) );
		exit(1);
	}

	int shm_id;
	shm_id = shmget( key, sizeof(unsigned int), 0644 | IPC_CREAT );
	if ( -1 == shm_id )
	{
		fprintf( stderr, "[Error] shmget share memory create fail -> %s\n", strerror(errno) );
		exit(1);
	}
	g_monitor.shm_id = shm_id;

	g_monitor.ipc_monitor_flag = shmat( shm_id, NULL, 0 );
	if ( !g_monitor.ipc_monitor_flag )
	{
		fprintf( stderr, "[Error] shmat get data fail -> %s\n", strerror(errno) );
		exit(1);
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

void io_monitor_user_interaction ()
{
	char user_key[BUFSIZ];
	printf( "off(o) read(r) write(w) pstree(p) env(e) all(a) kill(k)\n" );
	printf( "input monitor command: " );
	scanf( "%s", user_key );

	int key;
	for ( int i = 0; user_key[i]; ++i )
	{
		key = user_key[i];
		switch ( key )
		{
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

			case IO_MONITOR_USER_KEY_MONITOR_ALL:
				*(g_monitor.ipc_monitor_flag) = IO_MONITOR_IPC_MONITOR_ALL;
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

		// create share memory for IPC
		create_ipc_shm();

		// get user setting
		if ( g_opts.interactive_mode )
		{
			io_monitor_user_interaction();
		}
		else
		{
			*(g_monitor.ipc_monitor_flag) = IO_MONITOR_IPC_MONITOR_READ | IO_MONITOR_IPC_MONITOR_WRITE;
		}

		int status;
		pid_t pid;
		if ( 0 == (pid = fork()) )
		{
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

			register_monitor_signal_handlers();
			register_monitor_atext_works();

			printf( "* Monitor information:\n" );
			printf( "--------------------------\n" );
			printf( "libc version = %s\n", gnu_get_libc_version() );
			printf( "monitor cmd  = %s\n", g_monitor.cmd );
			printf( "tmp so path  = %s\n", g_monitor.tmp_so_name );
			printf( "report dir   = %s\n", g_monitor.result_dir );
			printf( "child pid    = %d\n", g_monitor.child_pid );
			printf( "shm ID       = %d\n", g_monitor.shm_id );

			if ( g_opts.interactive_mode )
			{
				while( true )
				{
					io_monitor_user_interaction();
				}
			}
			else
			{
				if ( -1 != waitpid( g_monitor.child_pid, &status, 0 ) )
				{
					printf( "Child pid=%d terminated with status=%d\n", g_monitor.child_pid, status );
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

