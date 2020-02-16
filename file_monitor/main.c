#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include "file_monitor.h"

int main ( int argc, char **argv )
{
	dir_monitor_inotify( argv[1] );
			
	return EXIT_SUCCESS;
}

