#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

int main ( int argc, char **argv )
{
	if ( argc == 2 )
	{
		remove( argv[1] );
	}

	return EXIT_SUCCESS;
}

