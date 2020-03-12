#ifndef MISC_H
#define MISC_H

#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

extern void __init_monitor ();
extern void __init_pid_info ( char *pid_info );
extern FILE *__create_report_file ( char *type, char *exec, char *event_file );
extern void __dump_data_to_report ( FILE *fout, const void *buf, size_t n_bytes );
extern void __get_proc_fd_name ( char *buf, pid_t pid, int fd );
extern void __get_proc_exec_name ( char *buf, pid_t pid );
extern void __get_proc_cmd ( char *buf, pid_t pid );
extern void __print_backtrace ();

extern ssize_t (*libc_read) (int , void *, size_t);
extern ssize_t (*libc_write) (int , const void *, size_t);
extern int (*libc_fflush) (FILE *);
extern int (*libc_fputc) (int, FILE *);
extern int (*libc_printf) (const char*, ...);
extern int (*libc_sprintf) (char *, const char*, ...);
extern int (*libc_fprintf) (FILE *, const char*, ...);
extern int (*libc_vprintf) (const char*, va_list);
extern int (*libc_vsprintf) (char *, const char*, va_list);
extern int (*libc_vfprintf) (FILE *, const char*, va_list);


#endif

