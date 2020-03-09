#ifndef MISC_H
#define MISC_H

#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

extern void __init_monitor ();
extern void __init_pid_info ( char *pid_info );
extern FILE *__create_report_file ( char *type, char *exec, char *event_file );
extern void __dump_data_to_report ( FILE *fout, const void *buf, size_t n_bytes );
extern char *__get_proc_fd_name ( pid_t pid, int fd );
extern char *__get_proc_exec_name ( pid_t pid );

extern pthread_mutex_t g_mutex_read;
extern pthread_mutex_t g_mutex_write;
extern pthread_mutex_t g_mutex_fflush;
extern pthread_mutex_t g_mutex_fputc;

extern int (*libc_fflush) (FILE *);
extern int (*libc_fputc) (int, FILE *);
extern int (*libc_fprintf) (FILE *, const char*, ...);


#endif

