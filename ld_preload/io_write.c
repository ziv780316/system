#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "misc.h"

ssize_t write ( int fd, const void *buf, size_t n )
{
	pthread_mutex_lock( &g_mutex );

	// get information from monitor 
	__init_monitor();

	// link symbol occur in next library (i.e. origin remove in libc.so)
	ssize_t (*libc_write) (int, const void *, size_t) = (ssize_t (*) (int, const void *, size_t)) dlsym( RTLD_NEXT, "write" );
	if ( NULL == libc_write )
	{
		fprintf( stderr, "[Error] RTLD link function %s fail\n", __func__ );
		abort();
	}

	// call origin write in libc.so
	ssize_t status;	
	status = libc_write( fd, buf, n );
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
		fprintf( fout, "[write] process=%s exec=%s write fd=%d file=\"%s\" status=fail error=\"%s\"\n", pid_info, exec_name, fd, file_name, strerror(errno_store) );
	}
	else
	{
		ssize_t n_write = status;
		fprintf( fout, "[write] process=%s exec=%s write fd=%d file=\"%s\" bytes=%ld status=ok\n", pid_info, exec_name, fd, file_name, n_write );
		if ( n_write > 0 )
		{
			// non EOF
			__dump_data_to_report ( fout, buf, n_write );
		}
	}
	
	fclose( fout );

	pthread_mutex_unlock( &g_mutex );

	return status;
}

