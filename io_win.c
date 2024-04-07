#include "io.h"

#if IO_PLATFORM_WINDOWS

#include <string.h>

/*
 * Declare Windows symbols locally to avoid including windows.h
 */

#define ERROR_IO_PENDING 997l

extern int ReadFile(void *handle, void *dst, unsigned long max, unsigned long *num, struct io_overlap *ov);
extern int WriteFile(void *handle, const void *src, unsigned long max, unsigned long *num, struct io_overlap *ov);
extern void *CreateIoCompletionPort(void *handle, void *existing_ioport, unsigned long *ptr, unsigned long num_threads);
extern int   CloseHandle(void *handle);
extern unsigned long GetLastError();
extern int GetQueuedCompletionStatus(void *ioport, unsigned long *num, unsigned long *key, struct io_overlap **ov, unsigned long timeout);

bool io_context_init(struct io_context *ioc,
                     struct io_operation *ops,
                     uint32_t max_ops)
{
    io_handle handle = CreateIoCompletionPort(IO_INVALID_HANDLE, NULL, 0, 1);
    if (handle == IO_INVALID_HANDLE)
        return false;

    ioc->handle = handle;
    ioc->max_ops = max_ops;
    ioc->ops = ops;
    return true;
}

void io_context_free(struct io_context *ioc)
{
    CloseHandle(ioc->handle);
}

static struct io_operation *alloc_op(struct io_context *ioc)
{
    for (uint32_t i = 0; i < ioc->max_ops; i++)
        if (ioc->ops[i].type == IO_VOID)
            return &ioc->ops[i];
    return NULL;
}

bool io_start_recv(struct io_context *ioc, io_handle handle,
                   void *dst, uint32_t max, void *user)
{
    struct io_operation *op = alloc_op(ioc);
    if (op == NULL)
        return false;

    memset(&op->ov, 0, sizeof(struct io_overlap));

    int ok = ReadFile(handle, dst, max, NULL, &op->ov);
	if (!ok && GetLastError() != ERROR_IO_PENDING)
		return false;

    op->user = user;
    op->type = IO_RECV;
    return true;
}

bool io_start_send(struct io_context *ioc, io_handle handle,
                   void *src, uint32_t num, void *user)
{
    struct io_operation *op = alloc_op(ioc);
    if (op == NULL)
        return false;

    memset(&op->ov, 0, sizeof(struct io_overlap));

    int ok = WriteFile(handle, src, num, NULL, &op->ov);
	if (!ok && GetLastError() != ERROR_IO_PENDING)
		return false;

    op->user = user;
    op->type = IO_SEND;
    return true;
}

bool io_start_accept(struct io_context *ioc, io_handle handle, void *user)
{
    // TODO
    return false;
}

void io_wait(struct io_context *ioc, struct io_event *ev)
{
    // TODO
}

#endif