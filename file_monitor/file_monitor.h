#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <stdbool.h>

// File Monitor API
void file_monitor_inotify ( char *file_path );
void dir_monitor_inotify ( char *dir_path );
void file_monitor_fanotify ( char *file_path );

// Auxiliary functions
bool check_is_dir ( char *path );
bool check_file_exist ( char *path );

#endif

