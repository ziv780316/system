#ifndef OPTS_H
#define OPTS_H

#include <stdbool.h>
#include "io_monitor.h"

typedef struct
{
	char *cmd;
	char *output_dir;
	char *so_path;

	monitor_type_t monitor_type;
	dump_type_t dump_type;

	bool interactive_mode;
	bool debug;
} opt_t;

extern void show_help ();
extern void parse_cmd_options ( int argc, char **argv );
extern opt_t g_opts;

#endif
