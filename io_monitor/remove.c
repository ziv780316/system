#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdbool.h>

#include "misc.h"

// link in LD_PRELOAD
int remove ( const char *path )
{
	// link symbol occur in next library (i.e. origin remove in libc.so)
	int (*libc_remove) (const char *) = (int (*) (const char *)) dlsym( RTLD_NEXT, "remove" );
	if ( NULL == libc_remove )
	{
		fprintf( stderr, "[Error] RTLD link function %s fail\n", __func__ );
		abort();
	}

	// call origin remove in libc.so
	int status;	
	status = libc_remove( path );
	int errno_store = errno;	

	// show information that monitor file remove by which process
	char pid_info[BUFSIZ];
	init_pid_info( pid_info );
	FILE *fout = create_report_file();

	if ( 0 == status )
	{
		fprintf( fout, "[remove] process %s remove \"%s\" status=ok\n", pid_info, path );
	}
	else
	{
		fprintf( fout, "[remove] process %s remove \"%s\" status=fail error=\"%s\"\n", pid_info, path, strerror(errno_store) );
	}

	return status;
}

int unlink ( const char *path )
{
	// link symbol occur in next library (i.e. origin unlink in libc.so)
	int (*libc_unlink) (const char *) = (int (*) (const char *)) dlsym( RTLD_NEXT, "unlink" );
	if ( NULL == libc_unlink )
	{
		fprintf( stderr, "[Error] RTLD link function %s fail\n", __func__ );
		abort();
	}

	// call origin unlink in libc.so
	int status;	
	status = libc_unlink( path );
	int errno_store = errno;	

	// show information that monitor file unlink by which process
	char pid_info[BUFSIZ];
	init_pid_info( pid_info );
	FILE *fout = create_report_file();

	if ( 0 == status )
	{
		fprintf( fout, "[unlink] process %s unlink \"%s\" status=ok\n", pid_info, path );
	}
	else
	{
		fprintf( fout, "[unlink] process %s unlink \"%s\" status=fail error=\"%s\"\n", pid_info, path, strerror(errno_store) );
	}

	return status;
}
