#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

int main ( int argc, char **argv )
{
	printf( "123" );
	char buf[BUFSIZ];
	sprintf( buf, "hihi999" );
	exit (1);

	return EXIT_SUCCESS;
}

