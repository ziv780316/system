#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int main ( int argc, char **argv )
{
	char buf[BUFSIZ];
	strcpy( buf, "/tmp/ttt.XXXXXX" );
	int fd = mkstemp( buf );
	fprintf( stderr, "create %s\n", buf );
	if ( -1 == fd )
	{
		fprintf( stderr, "[error] create tmpfile fail -> %s\n", strerror(errno) );
		exit(1);
	}
	write( fd, "hi", 2 );
	unlink( buf );
	unlink( "aa" );

	return EXIT_SUCCESS;
}

