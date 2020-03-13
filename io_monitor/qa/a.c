#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

int main ( int argc, char **argv )
{
	printf( "123" );
	printf( "xxx\n" );
	fprintf( stderr, "xxx\n" );
	char buf[BUFSIZ];
	sprintf( buf, "hihi999" );

	return EXIT_SUCCESS;
}

