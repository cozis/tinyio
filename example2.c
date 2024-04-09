#include <stdio.h>
#include <assert.h>
#include "io2.h"

#define MAX_RES 100
#define MAX_OPS 100

int main(void)
{
    int port = 8080;

    fprintf(stderr, "port=%d\n", port);

    struct io_operation ops[MAX_OPS];
    struct io_resource  res[MAX_RES];
    struct io_context ioc;
    
    if (!io_global_init()) {
        fprintf(stderr, "Couldn't perform the global initialization\n");
        return -1;
    }

    if (!io_init(&ioc, res, ops, MAX_RES, MAX_OPS)) {
        fprintf(stderr, "Couldn't initialize I/O context\n");
        return -1;
    }

    io_handle socket = io_start_server(&ioc, NULL, port);
    if (socket == IO_INVALID) {
        fprintf(stderr, "Couldn't start listening\n");
        return -1;
    }
    if (!io_accept(&ioc, NULL, socket)) {
        fprintf(stderr, "Couldn't start accept operation\n");
        return -1;
    }

    for (;;) {
        struct io_event ev;
        io_wait(&ioc, &ev);

        assert(ev.optype == IO_ACCEPT);
        io_handle accepted = ev.accepted;

        fprintf(stderr, "Accepted\n");

        io_close(&ioc, accepted);

        if (!io_accept(&ioc, NULL, socket)) {
            fprintf(stderr, "Couldn't start accept operation\n");
            return -1;
        }
    }

    io_free(&ioc);
    io_global_free();
    return 0;
}