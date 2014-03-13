#include <stdio.h>
#include "dir_monitor.h"

/* ------------------------------------------------------------------------- */

static void test_create(struct event_handler* h, const char* dir_path,
                        const char* fname)
{
    printf("File %s/%s is created.\n", dir_path, fname);
}

static void test_modify(struct event_handler* h, const char* dir_path,
                        const char* fname)
{
    printf("File %s/%s is modified.\n", dir_path, fname);
}

static void test_remove(struct event_handler* h, const char* dir_path,
                        const char* fname)
{
    printf("File %s/%s is removed.\n", dir_path, fname);
}

static void test_destructor(struct event_handler* h, const char* dir_path,
                            const char* fname)
{
    printf("monitor for %s/%s is removed.\n", dir_path, fname);
}

static struct event_operations test_event_operations = {
    .create     =   test_create,
    .modify     =   test_modify,
    .remove     =   test_remove,
    .destructor =   test_destructor,
};

static struct event_handler test_event_handler = {
    .ops    =   &test_event_operations,
};

/* ------------------------------------------------------------------------- */

#include <unistd.h>

int main(void)
{
    struct dir_monitor* d;
    const char* dir_path = "/tmp";

    d = dir_monitor_init(dir_path);
    if (!d)
        return 0;

    dir_monitor_add_handler(d, "abc", &test_event_handler);
    dir_monitor_add_handler(d, "def", &test_event_handler);

    sleep(5);

    dir_monitor_destroy(d);

    return 0;
}
