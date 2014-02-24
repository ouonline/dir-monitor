#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>

#include "dir-monitor.h"
#include "../mm/mm.h"

#define EVENT_BUFSIZE 1024

struct event_handler_item {
    struct list_node node;
    struct event_handler* handler;
};

#define oom_exit() exit(EXIT_FAILURE)

/* ------------------------------------------------------------------------- */

static inline void handle_event_create(struct event_handler* h,
                                       const char* dir_path,
                                       const char* fname)
{
    if (h->ops->create)
        h->ops->create(h, dir_path, fname);
}

static inline void handle_event_modify(struct event_handler* h,
                                       const char* dir_path,
                                       const char* fname)
{
    if (h->ops->modify)
        h->ops->modify(h, dir_path, fname);
}

static inline void handle_event_remove(struct event_handler* h,
                                       const char* dir_path,
                                       const char* fname)
{
    if (h->ops->remove)
        h->ops->remove(h, dir_path, fname);
}

static inline void handle_event_destructor(struct event_handler* h,
                                           const char* dir_path,
                                           const char* fname)
{
    if (h->ops->destructor)
        h->ops->destructor(h, dir_path, fname);
}

static void for_each_handler_safe(struct file_entry* entry,
                                  const char* dir_path,
                                  event_handler_func_t func)
{
    struct list_node *node, *next;

    pthread_rwlock_wrlock(&entry->f_lock);
    list_for_each_safe (node, next, &entry->handler_list) {
        struct event_handler_item* item;
        item = list_entry(node, struct event_handler_item, node);
        func(item->handler, dir_path, entry->name);
        mm_free(item);
    }
    pthread_rwlock_unlock(&entry->f_lock);
}

static void for_each_handler(struct file_entry* entry,
                             const char* dir_path,
                             event_handler_func_t func)
{
    struct list_node* node;

    pthread_rwlock_rdlock(&entry->f_lock);
    list_for_each (node, &entry->handler_list) {
        struct event_handler_item* item;
        item = list_entry(node, struct event_handler_item, node);
        func(item->handler, dir_path, entry->name);
    }
    pthread_rwlock_unlock(&entry->f_lock);
}

/* ------------------------------------------------------------------------- */

static inline struct file_entry* file_entry_get(struct file_entry* entry)
{
    atomic_inc(&entry->refcount);
    return entry;
}

static inline void __file_entry_destroy(struct dir_monitor* d,
                                        struct file_entry* entry)
{
    for_each_handler_safe(entry, d->path, handle_event_destructor);
    pthread_rwlock_destroy(&entry->f_lock);
    mm_free(entry);
}

static inline void file_entry_put(struct dir_monitor* d,
                                  struct file_entry* entry)
{
    if (atomic_dec_return(&entry->refcount) == 0)
        __file_entry_destroy(d, entry);
}

static inline struct file_entry* __get_file_entry_by_wd(struct dir_monitor* d,
                                                        int wd)
{
    struct list_node* node;

    list_for_each (node, &d->entry_list) {
        struct file_entry* entry = list_entry(node, struct file_entry, node);
        if (entry->wd == wd)
            return file_entry_get(entry);
    }

    return NULL;
}

static inline struct file_entry* get_file_entry_by_wd(struct dir_monitor* d,
                                                      int wd)
{
    struct file_entry* entry;

    pthread_rwlock_rdlock(&d->entry_list_lock);
    entry = __get_file_entry_by_wd(d, wd);
    pthread_rwlock_unlock(&d->entry_list_lock);

    return entry;
}

static inline struct file_entry* __get_file_entry_by_name(struct dir_monitor* d,
                                                          const char* fname)
{
    struct list_node* node;

    list_for_each (node, &d->entry_list) {
        struct file_entry* entry = list_entry(node, struct file_entry, node);
        if (strcmp(entry->name, fname) == 0)
            return file_entry_get(entry);
    }

    return NULL;
}

static inline struct file_entry* get_file_entry_by_name(struct dir_monitor* d,
                                                        const char* fname)
{
    struct file_entry* entry;

    pthread_rwlock_rdlock(&d->entry_list_lock);
    entry = __get_file_entry_by_name(d, fname);
    pthread_rwlock_unlock(&d->entry_list_lock);

    return entry;
}

static inline void update_entry_wd(struct file_entry* entry, int new_wd)
{
    pthread_rwlock_wrlock(&entry->f_lock);
    entry->wd = new_wd;
    pthread_rwlock_unlock(&entry->f_lock);
}

static inline int inotify_add_new_entry(struct dir_monitor* d,
                                        const char* fname)
{
    int wd;
    char* fpath;

    fpath = mm_alloc(strlen(d->path) + 1 + strlen(fname) + 1);
    if (!fpath)
        oom_exit();

    sprintf(fpath, "%s/%s", d->path, fname);
    wd = inotify_add_watch(d->fd, fpath,
                           IN_CLOSE_WRITE | IN_DELETE_SELF);
    mm_free(fpath);

    return wd;
}

static inline struct file_entry* file_entry_init(struct dir_monitor* d,
                                                 const char* fname)
{
    struct file_entry* entry;

    entry = mm_alloc(sizeof(struct file_entry) + strlen(fname) + 1);
    if (!entry)
        oom_exit();

    atomic_set(&entry->refcount, 0);
    list_init(&entry->node);
    list_init(&entry->handler_list);
    pthread_rwlock_init(&entry->f_lock, NULL);
    strcpy(entry->name, fname);
    entry->wd = inotify_add_new_entry(d, fname);

    return entry;
}

/* ------------------------------------------------------------------------- */

static inline void on_modify(struct dir_monitor* d,
                             struct inotify_event* e)
{
    struct file_entry* entry;

    entry = get_file_entry_by_wd(d, e->wd);
    if (entry) {
        for_each_handler(entry, d->path, handle_event_modify);
        file_entry_put(d, entry);
    }
}

static inline void on_remove(struct dir_monitor* d,
                             struct inotify_event* e)
{
    struct file_entry* entry;

    if (e->mask & IN_ISDIR)
        return;

    inotify_rm_watch(d->fd, e->wd);

    entry = get_file_entry_by_wd(d, e->wd);
    if (!entry)
        return;

    update_entry_wd(entry, 0);
    for_each_handler(entry, d->path, handle_event_remove);

    file_entry_put(d, entry);
}

static inline void on_create(struct dir_monitor* d,
                             struct inotify_event* e)
{
    int wd;
    struct file_entry* entry;

    if (e->mask & IN_ISDIR)
        return;

    wd = inotify_add_new_entry(d, e->name);
    if (wd == -1)
        return;

    entry = get_file_entry_by_name(d, e->name);
    if (!entry)
        return;

    update_entry_wd(entry, wd);
    for_each_handler(entry, d->path, handle_event_create);

    file_entry_put(d, entry);
}

static void* monitor_thread(void* arg)
{
    int len = 0;
    char buf[EVENT_BUFSIZE], *cur = buf, *end;
    struct dir_monitor* d = arg;

    while (1) {
        len = read(d->fd, cur, EVENT_BUFSIZE - len);
        if (len <= 0) {
            perror("reading inotify event");
            break;
        }

        end = cur + len;

        while (cur + sizeof(struct inotify_event) <= end) {
            struct inotify_event* e = (struct inotify_event*)cur;

            if (cur + sizeof(struct inotify_event) + e->len > end)
                break;

            if (e->mask & IN_CLOSE_WRITE)
                on_modify(d, e);

            if ((e->mask & IN_DELETE_SELF) || (e->mask & IN_MOVED_FROM))
                on_remove(d, e);

            if ((e->mask & IN_CREATE) || (e->mask & IN_MOVED_TO))
                on_create(d, e);

            cur += sizeof(struct inotify_event) + e->len;
        }

        if (cur >= end) {
            cur = buf;
            len = 0;
        } else {
            len = end - cur;
            memmove(buf, cur, len);
            cur = buf + len;
        }
    }

    return NULL;
}

struct dir_monitor* dir_monitor_init(const char* dir_path)
{
    int err;
    struct dir_monitor* d;

    if (!dir_path)
        return NULL;

    d = mm_alloc(sizeof(struct dir_monitor) + strlen(dir_path) + 1);
    if (!d)
        oom_exit();

    d->fd = inotify_init();
    if (d->fd == -1) {
        perror("inotify_init");
        goto err;
    }

    err = inotify_add_watch(d->fd, dir_path,
                            IN_CREATE | IN_MOVED_TO | IN_MOVED_FROM);
    if (err == -1) {
        perror("inotify_add_watch for dir");
        goto err;
    }

    pthread_rwlock_init(&d->entry_list_lock, NULL);
    list_init(&d->entry_list);
    strcpy(d->path, dir_path);

    err = pthread_create(&d->pid, NULL, monitor_thread, d);
    if (err) {
        perror("pthread_create");
        goto err1;
    }

    return d;

err1:
    pthread_rwlock_destroy(&d->entry_list_lock);
    close(d->fd);
err:
    mm_free(d);
    return NULL;
}

static inline void __dir_monitor_add_entry(struct dir_monitor* d,
                                           struct file_entry* entry)
{
    pthread_rwlock_wrlock(&d->entry_list_lock);
    list_add_prev(&entry->node, &d->entry_list);
    pthread_rwlock_unlock(&d->entry_list_lock);
}

int dir_monitor_add_handler(struct dir_monitor* d, const char* fname,
                            struct event_handler* h)
{
    struct event_handler_item* node;
    struct file_entry* entry;

    if (!d || !fname || !h)
        return -1;

    node = mm_alloc(sizeof(struct event_handler_item));
    if (!node)
        oom_exit();

    node->handler = h;

    entry = get_file_entry_by_name(d, fname);
    if (entry) {
        pthread_rwlock_wrlock(&entry->f_lock);
        list_add_prev(&node->node, &entry->handler_list);
        pthread_rwlock_unlock(&entry->f_lock);

        file_entry_put(d, entry);
        return 0;
    }

    entry = file_entry_init(d, fname);

    list_add_prev(&node->node, &entry->handler_list);

    file_entry_get(entry); /* hold the new entry */
    __dir_monitor_add_entry(d, entry);

    return 0;
}

void dir_monitor_del_handler(struct dir_monitor* d, const char* fname,
                             struct event_handler* h)
{
    struct list_node* node;
    struct file_entry* entry;

    if (!d || !fname || !h)
        return;

    entry = get_file_entry_by_name(d, fname);
    if (!entry)
        return;

    pthread_rwlock_wrlock(&entry->f_lock);
    list_for_each (node, &entry->handler_list) {
        struct event_handler_item* item;
        item = list_entry(node, struct event_handler_item, node);
        if (item->handler == h) {
            __list_del(node);
            mm_free(item);
            goto end;
        }
    }

end:
    pthread_rwlock_unlock(&entry->f_lock);
    file_entry_put(d, entry);
}

static inline void __dir_monitor_del_entry(struct dir_monitor* d,
                                           struct file_entry* entry)
{
    pthread_rwlock_wrlock(&d->entry_list_lock);
    list_del(&entry->node);
    pthread_rwlock_unlock(&d->entry_list_lock);
}

void dir_monitor_del_entry(struct dir_monitor* d, const char* fname)
{
    struct file_entry* entry;

    if (!d || !fname)
        return;

    entry = get_file_entry_by_name(d, fname);
    if (!entry)
        return;

    if (entry->wd > 0)
        inotify_rm_watch(d->fd, entry->wd);

    __dir_monitor_del_entry(d, entry);

    file_entry_put(d, entry); /* release the refcount of get_*() */
    file_entry_put(d, entry); /* release the refcount of add() */
}

void dir_monitor_destroy(struct dir_monitor* d)
{
    struct list_node *node, *next;
    if (!d)
        return;

    pthread_cancel(d->pid);
    pthread_join(d->pid, NULL);

    list_for_each_safe (node, next, &d->entry_list) {
        struct file_entry* entry = list_entry(node, struct file_entry, node);
        __dir_monitor_del_entry(d, entry);
        /* destroy an entry withcout checking its refcount. pthread_cancel()
         * may kill the monitor thread before file_entry_put() is called. */
        __file_entry_destroy(d, entry);
    }

    pthread_rwlock_destroy(&d->entry_list_lock);

    close(d->fd);
    mm_free(d);
}
