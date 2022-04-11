#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void f4 ()
{
	int fd3 = open( "log2", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR );
	write( fd3, "no", 2 );
	close( fd3 );
}

void f3 ()
{
	f4();
}

void f2 ()
{
	f3();
}

void f1 ()
{
	f2();
}

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

	int fd2 = open( "log1", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR );
	write( fd2, "ok", 2 );
	close( fd2 );

	f1();

	FILE *fout = fopen( "log3", "w" );
	fprintf( fout, "123\n" );
	fclose( fout );

	FILE *fin = fopen( "case10.c", "r" );
	fgets( buf, BUFSIZ, fin );
	fprintf( stdout, "%s\n", buf );
	fclose( fin );

	int fd3 = open( "case10.c", O_RDONLY );
	read( fd3, buf, BUFSIZ );
	close( fd3 );

	return EXIT_SUCCESS;
}

