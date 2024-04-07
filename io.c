
#include "io.h"

#if IO_PLATFORM_WINDOWS

#include <string.h>

/*
 * Declare Windows symbols locally to avoid including windows.h
 */

#define GENERIC_READ  0x80000000ULL
#define GENERIC_WRITE 0x40000000ULL

#define CREATE_NEW    1
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define OPEN_ALWAYS   4

#define FILE_ATTRIBUTE_NORMAL 0x00000080ULL
#define FILE_FLAG_OVERLAPPED  0x40000000ULL

#define ERROR_IO_PENDING 997l

struct security_attr {
    unsigned long size;
    void *desc;
    int inherit_handle;
};

extern void*
CreateFileA(const char *name, unsigned long access,
            unsigned long share, struct security_attr *sec,
            unsigned long creation, unsigned long flags, 
            void *template);

extern int
ReadFile(void *handle, void *dst, unsigned long max,
         unsigned long *num, struct io_overlap *ov);

extern int
WriteFile(void *handle, const void *src, unsigned long max,
          unsigned long *num, struct io_overlap *ov);

extern void*
CreateIoCompletionPort(void *handle, void *existing_ioport,
                       unsigned long *ptr, unsigned long num_threads);

extern int
CloseHandle(void *handle);

extern unsigned long
GetLastError();

extern int
GetQueuedCompletionStatus(void *ioport, unsigned long *num, unsigned long *key, struct io_overlap **ov, unsigned long timeout);

bool io_context_init(struct io_context *ioc,
                     struct io_operation *ops,
                     uint32_t max_ops)
{
    io_handle handle = CreateIoCompletionPort(IO_INVALID_HANDLE, NULL, 0, 1);
    if (handle == IO_INVALID_HANDLE)
        return false;
    
    for (uint32_t i = 0; i < max_ops; i++)
        ops[i].type = IO_VOID;

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
                   void *dst, uint32_t max)
{
    if (handle == IO_INVALID_HANDLE)
        return false;

    struct io_operation *op = alloc_op(ioc);
    if (op == NULL)
        return false;

    memset(&op->ov, 0, sizeof(struct io_overlap));

    int ok = ReadFile(handle, dst, max, NULL, &op->ov);
	if (!ok && GetLastError() != ERROR_IO_PENDING)
		return false;

    op->type = IO_RECV;
    return true;
}

bool io_start_send(struct io_context *ioc, io_handle handle,
                   void *src, uint32_t num)
{
    if (handle == IO_INVALID_HANDLE)
        return false;

    struct io_operation *op = alloc_op(ioc);
    if (op == NULL)
        return false;

    memset(&op->ov, 0, sizeof(struct io_overlap));

    int ok = WriteFile(handle, src, num, NULL, &op->ov);
	if (!ok && GetLastError() != ERROR_IO_PENDING)
		return false;

    op->type = IO_SEND;
    return true;
}

bool io_start_accept(struct io_context *ioc, io_handle handle)
{
    if (handle == IO_INVALID_HANDLE)
        return false;

    // TODO
    return false;
}

static unsigned long
convert_timeout(int timeout)
{
    if (timeout < 0)
        return ~0U;
    else
        return timeout;
}

static struct io_operation *op_from_ov(struct io_overlap *ov)
{
    return (struct io_operation*) ((char*) ov - offsetof(struct io_operation, ov));
}

void io_wait(struct io_context *ioc, struct io_event *ev)
{
    void *user;
	struct io_overlap *ov;
    unsigned long num;
	int ok = GetQueuedCompletionStatus(ioc->handle, &num, (unsigned long*) &user, &ov, convert_timeout(-1));

    if (!ok) {

        if (ov == NULL) {
            /*
             * General failure
             */
            ev->error = true;
            ev->user  = NULL; // The user must discriminate between general errors and specific operation errors through the user pointer. Not ideal
            ev->type  = IO_VOID;
        } else {
            /*
             * Operation failure
             */

            struct io_operation *op = op_from_ov(ov);

            ev->error = true;
            ev->user  = user;
            ev->type  = op->type;

            switch (op->type) {
                default:break;
                case IO_RECV: ev->num = 0; break;
                case IO_SEND: ev->num = 0; break;
                case IO_ACCEPT: ev->handle = IO_INVALID_HANDLE; break;
            }

            op->type = IO_VOID; // Mark unused
        }
        return;
    }

    struct io_operation *op = op_from_ov(ov);

    ev->error = false;
    ev->user  = user;
    ev->type  = op->type;

    switch (op->type) {
        default:break;
        case IO_RECV: ev->num = num; break;
        case IO_SEND: ev->num = num; break;
        case IO_ACCEPT: /* TODO */ break;
    }

    op->type = IO_VOID; // Mark unused
}

io_handle io_open_file(struct io_context *ioc,
                       const char *name,
                       int flags, void *user)
{
    unsigned long access = 0;
	if (flags & IO_ACCESS_RD) access |= GENERIC_READ;
	if (flags & IO_ACCESS_WR) access |= GENERIC_WRITE;

	io_handle handle = CreateFileA(name, access, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (handle == IO_INVALID_HANDLE)
		return IO_INVALID_HANDLE;

    if (CreateIoCompletionPort(handle, ioc->handle, user, 0) == NULL) {
		CloseHandle(handle);
		return IO_INVALID_HANDLE;
	}

    return handle;
}

io_handle io_create_file(struct io_context *ioc,
                         const char *name,
                         int flags, void *user)
{
    unsigned long flags2 = 0;

	if (flags & IO_CREATE_CANTEXIST)
		flags2 = CREATE_NEW;
	else {
		if (flags & IO_CREATE_OVERWRITE)
			flags2 = CREATE_ALWAYS;
		else
			flags2 = OPEN_ALWAYS;
	}

	io_handle handle = CreateFileA(name, GENERIC_WRITE, 0, NULL, flags2, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (handle == IO_INVALID_HANDLE)
        return IO_INVALID_HANDLE;

    if (CreateIoCompletionPort(handle, ioc->handle, user, 0) == NULL) {
		CloseHandle(handle);
		return IO_INVALID_HANDLE;
	}

    return handle;
}

#endif


#if IO_PLATFORM_LINUX

#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static int 
io_uring_setup(unsigned entries,
               struct io_uring_params *p)
{
    return (int) syscall(SYS_io_uring_setup, entries, p);
}

static int
io_uring_enter(int ring_fd, unsigned int to_submit,
               unsigned int min_complete, unsigned int flags)
{
    return (int) syscall(SYS_io_uring_enter, ring_fd, to_submit, 
                         min_complete, flags, NULL, 0);
}

bool io_context_init(struct io_context *ioc,
                     struct io_operation *ops,
                     uint32_t max_ops)
{
    ioc->ops = ops;
    ioc->max_ops = max_ops;

    for (uint32_t i = 0; i < max_ops; i++) {
        ioc->ops[i].type = IO_VOID;
        ioc->ops[i].handle = IO_INVALID_HANDLE;
    }

    struct io_uring_params p;
    void *sq_ptr, *cq_ptr;
    /* See io_uring_setup(2) for io_uring_params.flags you can set */
    memset(&p, 0, sizeof(p));
    int fd = io_uring_setup(32, &p);
    if (fd < 0)
        return false;

    ioc->handle = fd;

    /*
     * io_uring communication happens via 2 shared kernel-user space ring
     * buffers, which can be jointly mapped with a single mmap() call in
     * kernels >= 5.4.
     */
    int sring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    int cring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    /* Rather than check for kernel version, the recommended way is to
     * check the features field of the io_uring_params structure, which is a 
     * bitmask. If IORING_FEAT_SINGLE_MMAP is set, we can do away with the
     * second mmap() call to map in the completion ring separately.
     */
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (cring_sz > sring_sz)
            sring_sz = cring_sz;
        cring_sz = sring_sz;
    }
    /* Map in the submission and completion queue ring buffers.
     *  Kernels < 5.4 only map in the submission queue, though.
     */
    sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (sq_ptr == MAP_FAILED) {
        // TODO: Cleanup
        return false;
    }
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        cq_ptr = sq_ptr;
    } else {
        /* Map in the completion queue ring buffer in older kernels separately */
        cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
        if (cq_ptr == MAP_FAILED) {
            // TODO: Cleanup
            return false;
        }
    }

    /* Save useful fields for later easy reference */
    ioc->submissions.head = (_Atomic unsigned*) (sq_ptr + p.sq_off.head);
    ioc->submissions.tail = (_Atomic unsigned*) (sq_ptr + p.sq_off.tail);
    ioc->submissions.mask = (unsigned*) (sq_ptr + p.sq_off.ring_mask);
    ioc->submissions.array = sq_ptr + p.sq_off.array;
    ioc->submissions.limit = p.sq_entries;

    /* Map in the submission queue entries array */
    ioc->submissions.entries = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
                                    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                                    fd, IORING_OFF_SQES);
    if (ioc->submissions.entries == MAP_FAILED) {
        // TODO: Cleanup
        return false;
    }

    /* Save useful fields for later easy reference */
    ioc->completions.head = cq_ptr + p.cq_off.head;
    ioc->completions.tail = cq_ptr + p.cq_off.tail;
    ioc->completions.mask = cq_ptr + p.cq_off.ring_mask;
    ioc->completions.entries = cq_ptr + p.cq_off.cqes;
    ioc->completions.limit = p.cq_entries;
    return true;
}

void io_context_free(struct io_context *ioc)
{
    close(ioc->handle);
}

static bool start_oper(struct io_context *ioc,
                       struct io_uring_sqe sqe)
{
    unsigned int mask = *ioc->submissions.mask;
    unsigned int tail = atomic_load(ioc->submissions.tail);
    unsigned int head = atomic_load(ioc->submissions.head);

    if (tail >= head + ioc->submissions.limit)
        return false;

    unsigned int index = tail & mask;
    ioc->submissions.entries[index] = sqe;
    ioc->submissions.array[index] = index;

    atomic_store(ioc->submissions.tail, tail+1);

    int ret = io_uring_enter(ioc->handle, 1, 0, 0);
    if (ret < 0)
        return false;
    
    return true;
}

static struct io_operation *alloc_op(struct io_context *ioc,
                                     io_handle handle, void **user)
{
    assert(handle != IO_INVALID_HANDLE);

    /*
     * Look for an empty struct and the struct associated to
     * this handle.
     */
    struct io_operation *ref = NULL;
    struct io_operation *empty = NULL;

    for (uint32_t i = 0; i < ioc->max_ops; i++) {

        struct io_operation *op = &ioc->ops[i];

        if (op->handle == handle) {
            ref = op;
            if (empty) break;
        } else {
            if (op->type == IO_VOID && op->handle == IO_INVALID_HANDLE) {
                empty = op;
                if (ref) break;
            }
        }
    }
    assert(ref && empty);

    *user = ref->user;

    /*
     * If the reference slot is unused, use that one,
     * else use the first empty one.
     */
    if (ref->type == IO_VOID)
        return ref;
    else
        return empty;
}

bool io_start_recv(struct io_context *ioc, io_handle handle,
                   void *dst, uint32_t max)
{
    if (handle == IO_INVALID_HANDLE)
        return false;

    void *user;
    struct io_operation *op;
    struct io_uring_sqe sqe;

    op = alloc_op(ioc, handle, &user);
    if (op == NULL)
        return false;

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_READ;
    sqe.fd   = (int) handle;
    sqe.addr = (uint64_t) dst;
    sqe.len  = max;
    sqe.user_data = (uint64_t) op;
    
    if (!start_oper(ioc, sqe))
        return false;

    op->user = user;    
    op->type = IO_RECV; // Commit operation structure
    return true;
}

bool io_start_send(struct io_context *ioc, io_handle handle,
                   void *src, uint32_t num)
{
    if (handle == IO_INVALID_HANDLE)
        return false;

    void *user;
    struct io_operation *op;
    struct io_uring_sqe sqe;

    op = alloc_op(ioc, handle, &user);
    if (op == NULL)
        return false;

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_WRITE;
    sqe.fd   = (int) handle;
    sqe.addr = (uint64_t) src;
    sqe.len  = num;
    sqe.user_data = (uint64_t) op;

    if (!start_oper(ioc, sqe))
        return false;

    op->user = user;
    op->type = IO_SEND; // Commit operation structure
    return true;
}

bool io_start_accept(struct io_context *ioc, io_handle handle)
{
    if (handle == IO_INVALID_HANDLE)
        return false;

    void *user;
    struct io_operation *op;
    struct io_uring_sqe sqe;

    op = alloc_op(ioc, handle, &user);
    if (op == NULL)
        return false;

    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_ACCEPT;
    sqe.fd = (int) handle;
    sqe.user_data = (uint64_t) op;

    if (!start_oper(ioc, sqe))
        return false;

    op->user = user;
    op->type = IO_ACCEPT; // Commit operation structure
    return true;
}

void io_wait(struct io_context *ioc, struct io_event *ev)
{
    /* --- Read barrier --- */
    unsigned int head = atomic_load(ioc->completions.head);
    unsigned int tail = atomic_load(ioc->completions.tail);

    if (head == tail) {
        
        /*
         * Completion queue is empty. Wait for some operations to complete.
         */
        int ret = io_uring_enter(ioc->handle, 0, 1, IORING_ENTER_GETEVENTS);
        if (ret < 0) {
            ev->error = true;
            return;
        }
    }

    struct io_uring_cqe *cqe;
    struct io_operation *op;

    cqe = &ioc->completions.entries[head & (*ioc->completions.mask)];

    op = (void*) cqe->user_data;
    ev->user = op->user;
    ev->type = op->type;
    ev->error = cqe->res < 0;

    if (ev->error == false) {
        switch (op->type) {
            case IO_VOID: /* UNREACHABLE */ break;
            case IO_RECV: ev->num = cqe->res; break;
            case IO_SEND: ev->num = cqe->res; break;
            case IO_ACCEPT: ev->handle = cqe->res; break;
        }
    }

    op->type = IO_VOID; // Mark unused

    /* --- write barrier --- */
    atomic_store(ioc->completions.head, head+1);
}

static struct io_operation*
unassociated_operation_struct(struct io_context *ioc)
{
    for (uint32_t i = 0; i < ioc->max_ops; i++) {
        struct io_operation *op = &ioc->ops[i];
        if (op->type == IO_VOID && op->handle == IO_INVALID_HANDLE)
            return op;
    }
    return NULL;
}

io_handle io_open_file(struct io_context *ioc,
                       const char *name,
                       int flags, void *user)
{
    struct io_operation *op;
    op = unassociated_operation_struct(ioc);
    if (op == NULL)
        return IO_INVALID_HANDLE;

    int flags2 = 0;
	if (flags & IO_ACCESS_RD) flags2 |= O_RDONLY;
	if (flags & IO_ACCESS_WR) flags2 |= O_WRONLY;

	io_handle fd = open(name, flags2);
	if (fd < 0)
		return IO_INVALID_HANDLE;

    op->handle = fd;
    op->user = user;
    return fd;
}

io_handle io_create_file(struct io_context *ioc,
                         const char *name,
                         int flags, void *user)
{
    struct io_operation *op;
    op = unassociated_operation_struct(ioc);
    if (op == NULL)
        return IO_INVALID_HANDLE;

    int flags2 = O_CREAT | O_WRONLY;

	if (flags & IO_CREATE_CANTEXIST)
		flags2 |= O_EXCL;
	else {
		if (flags & IO_CREATE_OVERWRITE)
			flags2 |= O_TRUNC;
	}

    // TODO: is 0666 ok?
	int fd = open(name, flags2, 0666);
	if (fd < 0)
		return IO_INVALID_HANDLE;

    op->handle = fd;
    op->user = user;
    return fd;
}

#endif
