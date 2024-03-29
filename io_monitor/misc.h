#ifndef MISC_H
#define MISC_H

#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include "io_monitor.h"

extern void __sync_ipc ();
extern void __link_libc_functions ();
extern void __init_pid_info ( char *pid_info );
extern FILE *__create_report_file ( char *type, char *exec, char *event_file );
extern void __dump_data_to_report ( FILE *fout, const void *buf, size_t n_bytes );
extern void __get_proc_fd_name ( char *buf, pid_t pid, int fd );
extern void __get_proc_exec_name ( char *buf, pid_t pid );
extern void __get_proc_cmd ( char *buf, pid_t pid );
extern void __print_all_parent_cmd ( FILE *fout, pid_t pid_start, pid_t pid_end );
extern char * __get_time_string();
extern void __print_backtrace ();
extern void __print_backtrace_n_deepth ( FILE *fout, int n_deepth );
extern int __is_in_monitor_list ( const char *func );

extern ssize_t (*libc_read) (int , void *, size_t);
extern ssize_t (*libc_write) (int , const void *, size_t);
extern size_t (*libc_fwrite) (const void *, size_t, size_t, FILE *);
extern size_t (*libc_fread) (const void *, size_t, size_t, FILE *);
extern int (*libc_fflush) (FILE *);
extern int (*libc_fputc) (int, FILE *);
extern int (*libc_fputs) (const char *, FILE *);
extern int (*libc_printf) (const char*, ...);
extern int (*libc_sprintf) (char *, const char*, ...);
extern int (*libc_fprintf) (FILE *, const char*, ...);
extern int (*libc_vprintf) (const char*, va_list);
extern int (*libc_vsprintf) (char *, const char*, va_list);
extern int (*libc_vfprintf) (FILE *, const char*, va_list);
extern int (*libc_fscanf) (FILE *, const char *, ...);
extern int (*libc_sscanf) (const char *, const char *, ...);
extern char (*libc_fgets) (char *s, int size, FILE *stream);
extern int (*libc_execle) (const char *path, const char *arg, ...);
extern pid_t (*libc_fork) ();
extern pid_t (*libc_vfork) ();
extern void (*libc_exit) (int);
extern void (*libc__exit) (int);
extern int (*libc_unlink) (const char *pathname);
extern int (*libc_remove) (const char *pathname);
extern int (*libc_open) (const char *, int, ...);
extern int (*libc_close) (int);
extern FILE *(*libc_fopen) (const char *, const char*);
extern int (*libc_fclose) (FILE *);

extern char *g_output_dir;
extern unsigned int *g_ipc_monitor_flag;
extern int g_ipc_n_monitor_function;
extern char *g_ipc_monitor_functions;

#endif

