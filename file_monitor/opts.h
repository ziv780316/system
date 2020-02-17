#ifndef OPTS_H
#define OPTS_H

#include <stdbool.h>

typedef enum {
	WATCH_TYPE_NONE,
	WATCH_TYPE_FILE,
	WATCH_TYPE_DIR,

} watch_type_t;

typedef struct
{
	char *watch_target_path;

	watch_type_t watch_type ;

	bool recursive_watch;

	bool debug;

} opt_t;

extern void show_help ();
extern void parse_cmd_options ( int argc, char **argv );
extern opt_t g_opts;

#endif
