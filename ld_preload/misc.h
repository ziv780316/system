#ifndef MISC_H
#define MISC_H

#include <sys/types.h>
#include <stdio.h>

extern void __init_monitor ();
extern void __init_pid_info ( char *pid_info );
extern FILE *__create_report_file ( char *type, char *exec, char *event_file );
extern void __dump_data_to_report ( FILE *fout, const void *buf, size_t n_bytes );
extern char *__get_proc_fd_name ( pid_t pid, int fd );
extern char *__get_proc_exec_name ( pid_t pid );


#endif

