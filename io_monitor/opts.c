#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "opts.h"

static void str_to_lower ( char *str );
static int is_str_nocase_match ( const char *str_a, const char *str_b );

opt_t g_opts = {
	.cmd = NULL,
	.output_dir = "/tmp",

	.monitor_type = MONITOR_READ,
	.dump_type = DUMP_ASCII,

	.interactive_mode = false,
	.debug = false,
};

void show_help ()
{
	printf( "*------------------------------------*\n" 
		"*              IO MONITOR            *\n"
		"*------------------------------------*\n" 
		"[Options]\n"
		"  -h  =>  show help\n"
		"  -c | --cmd          =>  specify monitor program with cmd\n"
		"  -o | --output_dir   =>  specify output log directory\n"
		"  -t | --dump_type    =>  specify dump type\n"
		"  -m | --monitor_type =>  specify monitor type\n"
		"  -i | --interactive  =>  interactive mode\n"
		"  -d | --debug        =>  debug\n"
		"\n"
		"* Support dump type:\n"
		"   none\n"
		"   ascii\n"
		"   hex\n"
		"\n"
		"* Monitor io type:\n"
		"   read\n"
		"   write\n"
		"   both\n"
		"\n"
		"[Example]\n"
		"io_monitor -c <cmd> -o <output_dir> -t ascii -m read\n"
		);
}

static void str_to_lower ( char *str )
{
	for ( int i = 0; '\0' != str[i]; ++i )
	{
		str[i] = tolower( str[i] );
	}
}

static int is_str_nocase_match ( const char *str_a, const char *str_b )
{
	char *a = (char *) calloc ( strlen(str_a) + 1, sizeof(char) );
	char *b = (char *) calloc ( strlen(str_b) + 1, sizeof(char) );
	bool is_same;
	strcpy( a, str_a );
	strcpy( b, str_b );
	str_to_lower( a );
	str_to_lower( b );
	is_same = (0 == strcmp( a, b ));
	free( a );
	free( b );
	return is_same;
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
			{"cmd", required_argument, 0, 'c'},
			{"output_dir", required_argument, 0, 'o'},
			{"dump_type", required_argument, 0, 't'},
			{"monitor_type", required_argument, 0, 'm'},
			{"interactive", no_argument, 0, 'i'},
			{"debug", no_argument, 0, 'd'},
			{0, 0, 0, 0}
		};

		// getopt_long stores the option index here
		int option_index = 0;

		c = getopt_long( argc, argv, "hc:o:t:m:di", long_options, &option_index );

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

			case 'c':
				g_opts.cmd = strdup( optarg );
				break;

			case 'o':
				g_opts.output_dir = strdup( optarg );
				break;

			case 't':
				if ( is_str_nocase_match( "none", optarg ) )
				{
					g_opts.dump_type = DUMP_NONE;
				}
				else if ( is_str_nocase_match( "ascii", optarg ) )
				{
					g_opts.dump_type = DUMP_ASCII;
				}
				else if ( is_str_nocase_match( "hex", optarg ) )
				{
					g_opts.dump_type = DUMP_HEX;
				}
				else
				{
					fprintf( stderr, "[Error] unknown dump type %s\n", optarg );
					exit(1);
				}
				break;

			case 'm':
				if ( is_str_nocase_match( "read", optarg ) )
				{
					g_opts.monitor_type = MONITOR_READ;
				}
				else if ( is_str_nocase_match( "write", optarg ) )
				{
					g_opts.monitor_type = MONITOR_WRITE;
				}
				else if ( is_str_nocase_match( "both", optarg ) )
				{
					g_opts.monitor_type = MONITOR_BOTH;
				}
				else
				{
					fprintf( stderr, "[Error] unknown monitor type %s\n", optarg );
					exit(1);
				}
				break;

			case 'd':
				g_opts.debug = true;
				break;

			case 'i':
				g_opts.interactive_mode = true;
				break;

			case '?':
				// getopt_long already printed an error message 
				break;

			default:
				exit(1);
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
	if ( !g_opts.cmd )
	{
		fprintf( stderr, "[Error] please specify monitor cmd by '-c <cmd>'\n" );
		exit(1);
	}

	g_monitor.cmd = strdup( g_opts.cmd );
	g_monitor.result_dir = strdup( g_opts.output_dir );
	g_monitor.dump_type = g_opts.dump_type;
	g_monitor.monitor_type = g_opts.monitor_type;
	g_monitor.debug = g_opts.debug;

	if ( g_opts.interactive_mode )
	{
		g_monitor.monitor_type = MONITOR_BOTH;
	}
}

