#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

void file_monitor_inotify ( char *file_path );
void dir_monitor_inotify ( char *dir_path );
void file_monitor_fanotify ( char *file_path );

#endif

