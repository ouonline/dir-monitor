#ifndef __DIR_MONITOR_H__
#define __DIR_MONITOR_H__

#include <pthread.h>

#include "utils/list.h"
#include "utils/atomic.h"

struct dir_monitor {
    int fd;
    pthread_t pid;

    pthread_rwlock_t entry_list_lock;
    struct list_node entry_list;

    char path[0];
};

struct file_entry {
    int wd; /* protected by f_lock */
    struct list_node handler_list; /* protected by f_lock */
    pthread_rwlock_t f_lock;

    atomic_t refcount;
    struct list_node node;

    char name[0];
};

struct event_handler {
    struct event_operations* ops;
};

typedef void (*event_handler_func_t)(struct event_handler*,
                                     const char* dir_path,
                                     const char* fname);

struct event_operations {
    event_handler_func_t create;
    event_handler_func_t modify;
    event_handler_func_t remove;
    event_handler_func_t destructor;
};

struct dir_monitor* dir_monitor_init(const char* dir_path);
void dir_monitor_destroy(struct dir_monitor* d);

int dir_monitor_add_handler(struct dir_monitor* d, const char* fname,
                            struct event_handler* h);

/* the following functions will call event_operations->destructor(). */

void dir_monitor_del_handler(struct dir_monitor* d, const char* fname,
                             struct event_handler* h);

void dir_monitor_del_entry(struct dir_monitor* d, const char* fname);

#endif
