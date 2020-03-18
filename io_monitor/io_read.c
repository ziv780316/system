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
	__link_libc_functions();

	// get information from monitor 
	ssize_t status;	
	status = libc_read( fd, buf, n );
	int errno_store = errno;	

	// show information that monitor file read by which process
	char pid_info[BUFSIZ];
	__init_pid_info( pid_info );

	pid_t pid = syscall( SYS_getpid ); 
	char file_name[BUFSIZ];
	char exec_name[BUFSIZ];
	__get_proc_fd_name( file_name, pid, fd );
	__get_proc_exec_name( exec_name, pid );
	FILE *fout = __create_report_file( "read", exec_name, file_name );

	if ( fout )
	{
		if ( -1 == status )
		{
		}
		else
		{
			ssize_t n_read = status;
			libc_fprintf( fout, "[read] process=%s exec=%s read fd=%d file=\"%s\" bytes=%ld status=ok\n", pid_info, exec_name, fd, file_name, n_read );
			if ( n_read > 0 )
			{
				// non EOF
				__dump_data_to_report ( fout, buf, n_read );
			}
		}

		fclose( fout );
	}

	return status;
}

