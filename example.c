#include <stdio.h>
#include "io.h"

int main()
{
    struct io_operation ops[100];
    struct io_context ioc;
    if (!io_context_init(&ioc, ops, sizeof(ops)/sizeof(ops[0])))
        return -1;
    
    char msg[] = "Hello, world!\n";
    for (int i = 0; i < 10; i++) {
        if (!io_start_send(&ioc, io_get_stdout(), msg, sizeof(msg), NULL))
            fprintf(stderr, "ERROR\n");
    }

    for (int i = 0; i < 10; i++) {
        struct io_event ev;
        io_wait(&ioc, &ev);
        fprintf(stderr, "CONCLUDED\n");
    }

    io_context_free(&ioc);
    return 0;
}
