#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "file_monitor.h"
#include "opts.h"

//struct inotify_event
//{
//  int wd;		/* Watch descriptor.  */
//  uint32_t mask;	/* Watch mask.  */
//  uint32_t cookie;	/* Cookie to synchronize two events.  */
//  uint32_t len;		/* Length (including NULs) of name.  */
//  char name __flexarr;	/* name[]  */
//};
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

bool is_init_mutex = 0;
pthread_mutex_t g_lock;
int g_total_watch_dir_count = 1;

// =========================================
// File monitor API
// =========================================

static void *thread_dir_monitor_inotify ( void *arg )
{
	char *dir_path = (char *) arg;

	pthread_mutex_lock( &g_lock );

	g_total_watch_dir_count += 1;
	printf( "[Monitor] n_watch_dir=%d create thread TID=%ld to monitor %s\n", g_total_watch_dir_count, syscall( SYS_gettid ), dir_path );

	pthread_mutex_unlock( &g_lock );

	dir_monitor_inotify( dir_path );
	return NULL;
}

void file_monitor_inotify ( char *file_path )
{
	// create inotify instance
	int init_flag = 0; // flag can be IN_NONBLOCK or IN_CLOEXEC
	int fd = inotify_init1( init_flag ); // flag = 0 then inotify_init1 is the same to inotify_init
	if ( -1 == fd )
	{
		fprintf( stderr, "[Error] in %s: inotify_init1 fail -> %s\n", __func__, strerror(errno) );
		abort();
	}

	// add file to monitor
	// IN_ACCESS: read, exec
	// IN_MODIFY: write, truncate
	// IN_DELETE_SELF: monitor file be delete
	uint32_t mask = IN_ACCESS | IN_MODIFY | IN_OPEN | IN_DELETE_SELF;
	int wd = inotify_add_watch( fd, file_path, mask );
	if ( -1 == wd )
	{
		fprintf( stderr, "[Error] in %s: inotify_add_watch fail -> %s\n", __func__, strerror(errno) );
		abort();
	}

	char event_buf[EVENT_BUF_LEN];
	while ( true )
	{
		// block read event 
		ssize_t	n_read = read_n_byte( fd, event_buf, EVENT_BUF_LEN );
		struct inotify_event *event;
		printf( "[Monitor] read %ld event\n", n_read / EVENT_SIZE );
		for ( ssize_t i = 0; i < n_read; i += (EVENT_SIZE + event->len) )
		{
			event = (struct inotify_event *) &event_buf[i];
			if ( event->mask & IN_ACCESS )
			{
				printf( "[Monitor] file %s be accessed\n", file_path );
			}
			else if ( event->mask & IN_MODIFY )
			{
				printf( "[Monitor] file %s be modified\n", file_path );
			}
			else if ( event->mask & IN_OPEN )
			{
				printf( "[Monitor] file %s be open\n", file_path );
			}
			else if ( event->mask & IN_DELETE_SELF )
			{
				printf( "[Monitor] file %s be delete\n", file_path );
				goto end_monitor;
			}
			else if ( event->mask & IN_IGNORED )
			{
				printf( "[Monitor] file %s be ignored\n", file_path ); // follow by IN_DELETE_SELF
				goto end_monitor;
			}
			else
			{
				fprintf( stderr, "[Warning] unknow event mask %0#10x\n", event->mask );
			}
		}
	}

end_monitor:

	inotify_rm_watch( fd, wd );

	// close inotify instance
	close( fd );

}

void dir_monitor_inotify ( char *watch_dir )
{
	// initialize mutex for recursive watch by multi-threading
	if ( g_opts.recursive_watch )
	{
		if ( !is_init_mutex )
		{
			pthread_mutex_init( &g_lock, NULL );
		}
	}

	// create inotify instance
	int init_flag = 0; // flag can be IN_NONBLOCK or IN_CLOEXEC
	int fd = inotify_init1( init_flag ); // flag = 0 then inotify_init1 is the same to inotify_init
	if ( -1 == fd )
	{
		fprintf( stderr, "[Error] in %s: inotify_init1 fail -> %s\n", __func__, strerror(errno) );
		abort();
	}

	// add file to monitor
	// IN_ACCESS: read, exec
	// IN_MODIFY: write, truncate
	// IN_DELETE_SELF: monitor file be delete
	uint32_t mask = IN_ACCESS | // read
	                IN_MODIFY | // write
			IN_OPEN |   // open
			IN_CREATE | // creat
			IN_DELETE | // unlink event file
			IN_DELETE_SELF | // unlink watch target
			IN_CLOSE_WRITE | // close on write file
			IN_CLOSE_NOWRITE | // close on read file
			IN_MOVED_TO | // event file move into watch dir
			IN_MOVED_FROM | // event file move out from watch dir
			IN_MOVE_SELF | // watch target move
			IN_ATTRIB; // chmod
	int wd = inotify_add_watch( fd, watch_dir, mask );
	if ( -1 == wd )
	{
		fprintf( stderr, "[Error] in %s: inotify_add_watch fail -> %s\n", __func__, strerror(errno) );
		abort();
	}
	
	char event_buf[EVENT_BUF_LEN];
	char event_file_path[BUFSIZ];
	while ( true )
	{
		// pre-compute event counts
		size_t n_event = 0;
		ssize_t	n_read = read_n_byte( fd, event_buf, EVENT_BUF_LEN );
		struct inotify_event *event;
		for ( ssize_t i = 0; i < n_read; i += (EVENT_SIZE + event->len) )
		{
			event = (struct inotify_event *) &event_buf[i];
			++n_event;
		}
		if ( g_opts.debug )
		{
			printf( "[Monitor] read %ld event\n", n_event );
		}

		// show events
		for ( ssize_t i = 0; i < n_read; i += (EVENT_SIZE + event->len) )
		{
			event = (struct inotify_event *) &event_buf[i];

			bool is_dir;
			char *event_file_type = "directory"; // watch target directory
			if ( 0 != event->len ) 
			{
				// event file is under watch directory
				sprintf( event_file_path, "%s/%s", watch_dir, event->name );

				is_dir = event->mask & IN_ISDIR;
				if ( is_dir )
				{
					event_file_type = "directory";
				}
				else 
				{
					event_file_type = "file";
				}

				if ( event->mask & IN_CREATE )
				{
					printf( "[Monitor] %s %s be create\n", event_file_type, event_file_path );

					if ( is_dir && g_opts.recursive_watch )
					{
						pthread_t tid;
						int status;
						pthread_attr_t thread_attr;
						status = pthread_attr_init( &thread_attr );
						if ( 0 != status )
						{
							fprintf( stderr, "[Error] pthread_attr_init fail -> %s\n", strerror(errno) );
							abort();
						}

						char *sub_dir_path = (char *) malloc( (strlen(event_file_path) + 1) * sizeof(char) );
						strcpy( sub_dir_path, event_file_path );
						status = pthread_create( &tid, &thread_attr, thread_dir_monitor_inotify, sub_dir_path );
						if ( 0 != status )
						{
							fprintf( stderr, "[Error] pthread_create fail -> %s\n", strerror(errno) );
							abort();
						}
					}
				}
				else if ( event->mask & IN_DELETE )
				{
					printf( "[Monitor] %s %s be delete\n", event_file_type, event_file_path );
				}
				else if ( event->mask & IN_OPEN )
				{
					if ( !is_dir )
					{
						printf( "[Monitor] %s %s be opened\n", event_file_type, event_file_path );
					}
				}
				else if ( event->mask & IN_ACCESS )
				{
					if ( !is_dir )
					{
						printf( "[Monitor] %s %s be read accessed\n", event_file_type, event_file_path );
					}
				}
				else if ( event->mask & IN_MODIFY )
				{
					if ( !is_dir )
					{
						printf( "[Monitor] %s %s be write modified\n", event_file_type, event_file_path );
					}
				}
				else if ( event->mask & IN_CLOSE_WRITE )
				{
					if ( !is_dir )
					{
						printf( "[Monitor] %s %s be write close\n", event_file_type, event_file_path );
					}
				}
				else if ( event->mask & IN_CLOSE_NOWRITE )
				{
					if ( !is_dir )
					{
						printf( "[Monitor] %s %s be read close\n", event_file_type, event_file_path );
					}
				}
				else if ( event->mask & IN_MOVED_TO )
				{
					printf( "[Monitor] %s %s be move into %s\n", event_file_type, event_file_path, watch_dir );

					if ( is_dir && g_opts.recursive_watch )
					{
						pthread_t tid;
						int status;
						pthread_attr_t thread_attr;
						status = pthread_attr_init( &thread_attr );
						if ( 0 != status )
						{
							fprintf( stderr, "[Error] pthread_attr_init fail -> %s\n", strerror(errno) );
							abort();
						}

						char *sub_dir_path = (char *) malloc( (strlen(event_file_path) + 1) * sizeof(char) );
						strcpy( sub_dir_path, event_file_path );
						status = pthread_create( &tid, &thread_attr, thread_dir_monitor_inotify, sub_dir_path );
						if ( 0 != status )
						{
							fprintf( stderr, "[Error] pthread_create fail -> %s\n", strerror(errno) );
							abort();
						}
					}
				}
				else if ( event->mask & IN_MOVED_FROM )
				{
					printf( "[Monitor] %s %s be move out from %s\n", event_file_type, event_file_path, watch_dir );
				}
				else if ( event->mask & IN_ATTRIB )
				{
					printf( "[Monitor] %s %s be chmod\n", event_file_type, event_file_path );
				}
				else
				{
					if ( g_opts.debug )
					{
						fprintf( stderr, "[Warning] ignore event mask %0#10x\n", event->mask );
					}
				}
			}
			else
			{
				// event file is watch directory self
				if ( event->mask & IN_ATTRIB )
				{
					printf( "[Monitor] watch target %s be chmod\n", watch_dir );
				}
				else if ( event->mask & IN_DELETE_SELF )
				{
					printf( "[Monitor] watch target %s be delete\n", watch_dir );
					goto end_monitor;
				}
				else if ( event->mask & IN_IGNORED )
				{
					printf( "[Monitor] watch target %s be ignored\n", watch_dir ); // follow by IN_DELETE_SELF
					goto end_monitor;
				}
				else if ( event->mask & IN_MOVE_SELF )
				{
					printf( "[Monitor] watch target %s be move\n", watch_dir ); 
					goto end_monitor;
				}
				else
				{
					if ( g_opts.debug )
					{
						fprintf( stderr, "[Warning] ignore event mask %0#10x\n", event->mask );
					}
				}
			}
		}
	}

end_monitor:

	printf( "[Monitor] stop monitor %s\n", watch_dir );

	inotify_rm_watch( fd, wd );

	// close inotify instance
	close( fd );

	// re-count
	pthread_mutex_lock( &g_lock );
	g_total_watch_dir_count -= 1;
	pthread_mutex_unlock( &g_lock );
}

void file_monitor_fanotify ( char *file_path )
{
	// create inotify instance
	int init_flag = 0; // flag can be IN_NONBLOCK or IN_CLOEXEC
	int fd = inotify_init1( init_flag ); // flag = 0 then inotify_init1 is the same to inotify_init
	if ( -1 == fd )
	{
		fprintf( stderr, "[Error] in %s: inotify_init1 fail -> %s\n", __func__, strerror(errno) );
		abort();
	}

	// add file to monitor
	// IN_ACCESS: read, exec
	// IN_MODIFY: write, truncate
	uint32_t mask = IN_ACCESS | IN_MODIFY | IN_OPEN;
	int wd = inotify_add_watch( fd, file_path, mask );
	if ( -1 == wd )
	{
		fprintf( stderr, "[Error] in %s: inotify_add_watch fail -> %s\n", __func__, strerror(errno) );
		abort();
	}
	
	// block read event 
	char event_buf[EVENT_BUF_LEN];
	ssize_t	n_read = read_n_byte( fd, event_buf, EVENT_BUF_LEN );
	struct inotify_event *event;
	printf( "[Monitor] read %ld event\n", n_read / EVENT_SIZE );
	for ( ssize_t i = 0; i < n_read; i += (EVENT_SIZE + event->len) )
	{
		event = (struct inotify_event *) &event_buf[i];
		if ( event->mask & IN_ACCESS )
		{
			printf( "[Monitor] %s be accessed\n", file_path );
		}
		else if ( event->mask & IN_MODIFY )
		{
			printf( "[Monitor] %s be modified\n", file_path );
		}
		else if ( event->mask & IN_OPEN )
		{
			printf( "[Monitor] %s be open\n", file_path );
		}
		else
		{
			fprintf( stderr, "[Warning] unknow event mask %0#10x\n", event->mask );
		}
	}

	inotify_rm_watch( fd, wd );

	// close inotify instance
	close( fd );

}

// =========================================
// Auxiliary functions
// =========================================
ssize_t read_n_byte( int fd, void *buf, int len )
{
	ssize_t	n_read = read( fd, buf, len );
	if ( -1 == n_read )
	{
		fprintf( stderr, "[Error] in %s: read fail -> %s\n", __func__, strerror(errno) );
		abort();
	}
	return n_read;
}

int check_is_dir ( char *path )
{
	struct stat st_buf;
	if ( -1 == stat( path, &st_buf ) )
	{
		fprintf( stderr, "[Error] query target %s stat fail --> %s\n", path, strerror(errno) );
		return -1;
	}
	if ( S_ISDIR(st_buf.st_mode) )
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int check_file_exist ( char *path )
{
	struct stat st_buf;
	if ( -1 == stat( path, &st_buf ) )
	{
		if ( ENOENT == errno )
		{
			return 0;
		}
		else
		{
			return -1;
		}
	}

	return 1;
}

