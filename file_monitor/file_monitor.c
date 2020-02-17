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

#include "file_monitor.h"

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

static ssize_t read_n_byte( int fd, void *buf, int len )
{
	ssize_t	n_read = read( fd, buf, len );
	if ( -1 == n_read )
	{
		fprintf( stderr, "[Error] in %s: read fail -> %s\n", __func__, strerror(errno) );
		abort();
	}
	return n_read;
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
			else if ( event->mask & IN_DELETE_SELF )
			{
				printf( "[Monitor] %s be delete\n", file_path );
				goto end_monitor;
			}
			else if ( event->mask & IN_IGNORED )
			{
				printf( "[Monitor] %s be ignored\n", file_path ); // follow by IN_DELETE_SELF
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
	uint32_t mask = IN_ACCESS | IN_MODIFY | IN_OPEN | IN_CREATE | IN_DELETE | IN_DELETE_SELF;
	int wd = inotify_add_watch( fd, watch_dir, mask );
	if ( -1 == wd )
	{
		fprintf( stderr, "[Error] in %s: inotify_add_watch fail -> %s\n", __func__, strerror(errno) );
		abort();
	}
	
	bool is_dir;
	char *event_file_type;
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
		printf( "[Monitor] read %ld event\n", n_event );

		// show events
		for ( ssize_t i = 0; i < n_read; i += (EVENT_SIZE + event->len) )
		{
			event = (struct inotify_event *) &event_buf[i];
			if ( (0 != event->len) && !(event->mask & IN_DELETE ) )
			{
				sprintf( event_file_path, "%s/%s", watch_dir, event->name );
				if ( check_file_exist(event_file_path) )
				{
					is_dir = check_is_dir( event_file_path );
					if ( is_dir )
					{
						event_file_type = "directory";
					}
					else
					{
						event_file_type = "file";
					}
				}
				else
				{
					printf( "[Warning] query %s stat fail\n", event_file_path );
				}
			}

			if ( event->mask & IN_CREATE )
			{
				if ( 0 == event->len )
				{
					fprintf( stderr, "[Error] event->len=0 when file create in monitored directory\n" );
					abort();
				}
				printf( "[Monitor] in %s: %s %s be create\n", watch_dir, event_file_type, event->name );
			}
			else if ( event->mask & IN_DELETE )
			{
				if ( 0 == event->len )
				{
					fprintf( stderr, "[Error] event->len=0 when file delete in monitored directory\n" );
					abort();
				}
				printf( "[Monitor] in %s: entry %s be delete\n", watch_dir, event->name );
			}
			else if ( event->mask & IN_OPEN )
			{
				if ( 0 == event->len )
				{
					printf( "[Monitor] %s be opened\n", watch_dir );
				}
				else
				{
					printf( "[Monitor] in %s: %s %s be opened\n", watch_dir, event_file_type, event->name );
				}
			}
			else if ( event->mask & IN_ACCESS )
			{
				if ( 0 == event->len )
				{
					printf( "[Monitor] %s be accessed\n", watch_dir );
				}
				else
				{
					printf( "[Monitor] in %s: %s %s be accessed\n", watch_dir, event_file_type, event->name );
				}
			}
			else if ( event->mask & IN_MODIFY )
			{
				printf( "[Monitor] in %s: %s %s be modified\n", watch_dir, event_file_type, event->name );
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

bool check_is_dir ( char *path )
{
	struct stat st_buf;
	if ( -1 == stat( path, &st_buf ) )
	{
		fprintf( stderr, "[Error] query target %s stat fail --> %s\n", path, strerror(errno) );
		abort();
	}
	if ( S_ISDIR(st_buf.st_mode) )
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool check_file_exist ( char *path )
{
	struct stat st_buf;
	if ( -1 == stat( path, &st_buf ) )
	{
		if ( ENOENT == errno )
		{
			return false;
		}
	}

	return true;
}

