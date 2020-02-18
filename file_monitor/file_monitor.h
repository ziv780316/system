#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

// File Monitor API
void file_monitor_inotify ( char *file_path );
void dir_monitor_inotify ( char *dir_path );
void file_monitor_fanotify ( char *file_path );

// Auxiliary functions
ssize_t read_n_byte( int fd, void *buf, int len );
int check_is_dir ( char *path );
int check_file_exist ( char *path );

#endif

