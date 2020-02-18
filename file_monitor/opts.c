#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "file_monitor.h"
#include "opts.h"

opt_t g_opts = {
	.watch_target_path = NULL,
	.watch_type = WATCH_TYPE_NONE,
	.recursive_watch = false,
	.debug = false,
};

void show_help ()
{
	printf( "*------------------------------------*\n" 
		"*         File System Monitor        *\n"
		"*------------------------------------*\n" 
		"[Options]\n"
		"  -h  =>  show help\n"
		"  -i | --input       =>  specify watch target path\n"
		"  -r | --recursive   =>  recursive watch under target directory\n"
		"  -d | --debug       =>  show debug information\n"
		"\n"
		"[Example]\n"
		"file_monitor -i <target path> -r\n"
		);
}

void parse_cmd_options ( int argc, char **argv )
{
	int c;

	while ( true )
	{
		static struct option long_options[] =
		{
			// flag options
			{"help", no_argument, 0, 'h'},

			// setting options
			{"input", required_argument, 0, 'i'},
			{"recursive", no_argument, 0, 'r'},
			{"debug", no_argument, 0, 'd'},
			{0, 0, 0, 0}
		};

		// getopt_long stores the option index here
		int option_index = 0;

		c = getopt_long( argc, argv, "hdri:", long_options, &option_index );

		// detect the end of the options
		if ( -1 == c )
		{
			break;
		}

		switch ( c )
		{
			case 'h':
				show_help();
				exit( EXIT_SUCCESS );
				break;

			case 'i':
				g_opts.watch_target_path = (char *) malloc( (strlen(optarg) + 1) * sizeof(char) );
				strcpy( g_opts.watch_target_path, optarg );
				if ( '/' == g_opts.watch_target_path[strlen(optarg) - 1] )
				{
					g_opts.watch_target_path[strlen(optarg) - 1] = '\0';
				}
				break;

			case 'r':
				g_opts.recursive_watch = true;
				break;

			case '?':
				// getopt_long already printed an error message 
				break;

			default:
				abort ();
				break;
		}
	}

	// print any remaining command line arguments (not options)
	if (optind < argc)
	{
		fprintf( stderr, "[Warning] non-option ARGV-elements: " );
		while ( optind < argc )
		{
			fprintf( stderr, "%s ", argv[optind++] );
		}
		fprintf( stderr, "\n" );
	}

	// check arguments
	if ( 1 == check_is_dir(g_opts.watch_target_path) )
	{
		printf( "[Monitor] watch directory target %s\n", g_opts.watch_target_path );
		g_opts.watch_type = WATCH_TYPE_DIR;
	}
	else
	{
		printf( "[Monitor] watch file target %s\n", g_opts.watch_target_path );
		g_opts.watch_type = WATCH_TYPE_FILE;
	}
}

