#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "misc.h"

ssize_t read ( int fd, void *buf, size_t n )
{
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
	init_pid_info( pid_info );
	FILE *fout = create_report_file();

	char file_name[BUFSIZ] = {0};
	char fd_link_path[BUFSIZ] = {0};
	pid_t pid = syscall( SYS_getpid ); 
	sprintf( fd_link_path, "/proc/%d/fd/%d", pid, fd );
	if ( -1 == readlink( fd_link_path, file_name, BUFSIZ ) )
	{
		fprintf( stderr, "[Error] readlink %s fail in %s\n", fd_link_path, __func__ );
		abort();
	}

	static int dump_read_data = -1;
	if ( -1 == dump_read_data )
	{
		if ( getenv("LD_PRELOAD_REPORT_DUMP_READ_DATA") )
		{
			dump_read_data = true;
		}
		else
		{
			dump_read_data = false;
		}
	}

	if ( -1 == status )
	{
		fprintf( fout, "[read] process %s read fd=%d file=\"%s\" status=fail error=\"%s\"\n", pid_info, fd, file_name, strerror(errno_store) );
	}
	else
	{
		ssize_t n_read = status;
		fprintf( fout, "[read] process %s read fd=%d file=\"%s\" bytes=%ld status=ok\n", pid_info, fd, file_name, n_read );
		if ( dump_read_data )
		{
			
			fprintf( fout, "[read] dump data in ASCII:\n" );
			for ( ssize_t i = 0; i < n_read; ++i )
			{
				if ( ((char *)buf)[i] <= 128 )
				{
					fprintf( fout, "%c", ((char *)buf)[i] );
				}
				else
				{
					fprintf( fout, "." );
				}
			}
		}
	}

	return status;
}

