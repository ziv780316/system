#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>


// link in LD_PRELOAD
int remove ( const char *path )
{
	// gettid resolve thread TID to PID
	pid_t pid;
	pid = syscall( SYS_gettid ); 
	
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

	// show information that monitor file remove by which process
	if ( 0 == status )
	{
		printf( "[remove] process PID=%d remove \"%s\" status=ok\n", pid, path );
	}
	else
	{
		printf( "[remove] process PID=%d remove \"%s\" status=fail error=\"%s\"\n", pid, path, strerror(errno) );
	}

	return status;
}

