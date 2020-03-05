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

ssize_t read ( int fd, void *buf, size_t n )
{
	// get information from monitor 
	__init_monitor();

	// link symbol occur in next library (i.e. origin remove in libc.so)
	ssize_t (*libc_read) (int, void *, size_t) = (ssize_t (*) (int, void *, size_t)) dlsym( RTLD_NEXT, "read" );
	if ( NULL == libc_read )
	{
		fprintf( stderr, "[Error] RTLD link function %s fail\n", __func__ );
		abort();
	}

	// call origin read in libc.so
	ssize_t status;	
	status = libc_read( fd, buf, n );
	int errno_store = errno;	

	// show information that monitor file read by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	pid_t pid = syscall( SYS_getpid ); 
	char *file_name = __get_proc_fd_name( pid, fd );
	char *exec_name = __get_proc_exec_name( pid );
	FILE *fout = __create_report_file( "read", exec_name, file_name );

	if ( -1 == status )
	{
		fprintf( fout, "[read] process=%s exec=%s read fd=%d file=\"%s\" status=fail error=\"%s\"\n", pid_info, exec_name, fd, file_name, strerror(errno_store) );
	}
	else
	{
		ssize_t n_read = status;
		fprintf( fout, "[read] process=%s exec=%s read fd=%d file=\"%s\" bytes=%ld status=ok\n", pid_info, exec_name, fd, file_name, n_read );
		if ( n_read > 0 )
		{
			// non EOF
			__dump_data_to_report ( fout, buf, n_read );
		}
	}
	
	fclose( fout );

	return status;
}

