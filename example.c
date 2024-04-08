#include <stdio.h>
#include "io2.h"

#define NUM_OPS 3

int main()
{
    io_global_init();

    struct io_operation ops[100];
    struct io_resource  res[100];
    struct io_context ioc;
    if (!io_init(&ioc, res, ops, sizeof(res)/sizeof(res[0]), sizeof(ops)/sizeof(ops[0])))
        return -1;
    
    io_handle files[NUM_OPS];

    for (int i = 0; i < NUM_OPS; i++) {
        char name[1<<8];
        snprintf(name, sizeof(name), "file_%d.txt", i);
        files[i] = io_create_file(&ioc, name, IO_CREATE_CANTEXIST, NULL);
        if (files[i] == IO_INVALID_HANDLE)
            fprintf(stderr, "Couldn't create '%s'\n", name);
    }

    int started = 0;
    char msg[] = "Hello, world!\n";
    for (int i = 0; i < NUM_OPS; i++) {
        if (io_start_send(&ioc, files[i], msg, sizeof(msg)-1))
            started++;
        else
            fprintf(stderr, "ERROR\n");
    }

    for (int i = 0; i < started; i++) {
        struct io_event ev;
        io_wait(&ioc, &ev);
        fprintf(stderr, "CONCLUDED\n");
    }

    io_context_free(&ioc);
    io_global_free();
    return 0;
}
