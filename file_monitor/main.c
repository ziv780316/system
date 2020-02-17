#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#include "opts.h"
#include "file_monitor.h"

int main ( int argc, char **argv )
{
	if ( 1 == argc )
	{
		show_help();
	}
	else
	{
		parse_cmd_options( argc, argv );
	}

	setbuf( stdout, 0 );

	if ( WATCH_TYPE_FILE == g_opts.watch_type )
	{
		file_monitor_inotify ( g_opts.watch_target_path );
	}
	else if ( WATCH_TYPE_DIR == g_opts.watch_type )
	{
		dir_monitor_inotify ( g_opts.watch_target_path );
	}
			
	return EXIT_SUCCESS;
}

