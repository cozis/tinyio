
#include "io.h"

#if IO_PLATFORM_WINDOWS

#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

bool io_global_init(void)
{
    WSADATA data;
    int ret = WSAStartup(MAKEWORD(2, 2), &data);
    return ret == NO_ERROR;
}

void io_global_free(void)
{
    WSACleanup();
}

bool io_context_init(struct io_context   *ioc,
                     struct io_resource  *res,
                     struct io_operation *ops,
                     uint16_t max_res,
                     uint16_t max_ops)
{
    io_raw_handle raw_handle = CreateIoCompletionPort(IO_INVALID_HANDLE, NULL, 0, 1);
    if (raw_handle == INVALID_HANDLE_VALUE)
        return false;
    
    for (uint32_t i = 0; i < max_ops; i++)
        ops[i].type = IO_VOID;

    ioc->raw_handle = raw_handle;
    ioc->max_res = max_res;
    ioc->max_ops = max_ops;
    ioc->res = res;
    ioc->ops = ops;
    return true;
}

void io_context_free(struct io_context *ioc)
{
    for (uint32_t i = 0; i < ioc->max_res; i++)
        if (ioc->res[i].type != IO_RES_VOID)
            io_close(ioc, i);
    CloseHandle(ioc->raw_handle);
}

void io_close(struct io_context *ioc,
              io_handle handle)
{
    // TODO: Check handle

    struct io_resource *res = &ioc->res[handle];

    if (res->type == IO_RES_SOCKET)
        closesocket(res->raw_handle);
    else
        CloseHandle(res->raw_handle);

    uint16_t op_idx = res->head_operation;
    while (op_idx != -1) {
        struct io_operation *op;
        op = &ioc->ops[op_idx];
        op->type = IO_VOID;
        op_idx = op->next_operation;
    }

    res->typ = IO_RES_VOID;
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
    if (handle == IO_INVALID_HANDLE)
        return false;
    
    struct io_resource *res = &ioc->res[handle];

    struct io_operation *op;
    op = alloc_op(ioc);
    if (op == NULL)
        return false;

    memset(&op->ov, 0, sizeof(struct io_overlap));

    int ok = ReadFile(handle, dst, max, NULL, &op->ov);
	if (!ok && GetLastError() != ERROR_IO_PENDING)
		return false;

    op->type = IO_RECV;
    op->handle = handle;
    op->nextop = res->headop;
    res->headop = op - ioc->ops;
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
    op->handle = handle;
    op->nextop = res->headop;
    res->headop = op - ioc->ops;
    return true;
}

bool io_start_accept(struct io_context *ioc, io_handle handle)
{
    if (handle == IO_INVALID_HANDLE)
        return false;

    struct io_resource *rs = &ioc->res[handle];

    struct io_operation *op = alloc_op(ioc);
    if (op == NULL)
        return false;

    memset(&op->ov, 0, sizeof(struct io_overlap));
    
    SOCKET new_raw_handle = socket(AF_INET, SOCK_STREAM, 0);
    if (new_raw_handle == INVALID_HANDLE_VALUE)
        return false;

    LPFN_ACCEPTEX lpfnAcceptEx = NULL;
    GUID GuidAcceptEx = WSAID_ACCEPTEX;

    unsigned long num;
    int ret = WSAIoctl(rs->raw_handle,
             SIO_GET_EXTENSION_FUNCTION_POINTER,
             &GuidAcceptEx, sizeof(GuidAcceptEx), 
             &lpfnAcceptEx, sizeof(lpfnAcceptEx), 
             &num, NULL, NULL);
    if (ret == SOCKET_ERROR) {
        closesocket(new_raw_handle);
        return false;
    }

    _Static_assert(IO_SOCKADDR_IN_SIZE == sizeof(struct sockaddr_in));

    int ok = lpfnAcceptEx(handle2, rs->raw_handle, op->accept_buffer,
                 sizeof(op->accept_buffer) - ((sizeof(struct sockaddr_in) + 16) * 2),
                 sizeof(struct sockaddr_in) + 16, 
                 sizeof(struct sockaddr_in) + 16,
                 &num, &op->ov);
    if (!ok) {
        closesocket(new_raw_handle);
        return false;
    }

    op->type = IO_ACCEPT;
    op->handle = handle;
    op->nextop = res->headop;
    res->headop = op - ioc->ops;
    op->accept_handle = new_raw_handle;
    return true;
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
	int ok = GetQueuedCompletionStatus(ioc->raw_handle, &num, &user, &ov, convert_timeout(-1));

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
                
                case IO_ACCEPT:
                closesocket(op->accept_handle);
                op->accept_handle = IO_INVALID_HANDLE;
                break;
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
        case IO_ACCEPT: op->accept_handle; break;
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

io_handle io_listen(struct io_context *ioc,
                    const char *addr, int port,
                    void *user)
{
    return IO_INVALID_HANDLE;
}

#endif


#if IO_PLATFORM_LINUX

#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

bool io_global_init(void)
{
    return true;
}

void io_global_free(void)
{
}

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

void io_close(struct io_context *ioc,
              io_handle handle)
{
    for (uint32_t i = 0; i < ioc->max_ops; i++)
        if (ioc->ops[i].handle == handle) {
            assert(ioc->ops[i].type == IO_VOID);
            ioc->ops[i].handle = IO_INVALID_HANDLE;
            ioc->ops[i].user = NULL;
        }
    close(handle);
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

io_handle io_listen(struct io_context *ioc,
                    const char *addr, int port,
                    void *user)
{
    if (port < 1 || port > UINT16_MAX)
        return IO_INVALID_HANDLE;

    struct in_addr addr2;
    if (addr == NULL)
        addr2.s_addr = INADDR_ANY;
    else {
        if (1 != inet_pton(AF_INET, addr, &addr2))
            return IO_INVALID_HANDLE;
    }

    struct io_operation *op;
    op = unassociated_operation_struct(ioc);
    if (op == NULL)
        return IO_INVALID_HANDLE;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return IO_INVALID_HANDLE;
    
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in buf;
    buf.sin_family = AF_INET;
    buf.sin_port = htons(port);
    buf.sin_addr = addr2;
    if (bind(fd, (struct sockaddr*) &buf, sizeof(buf))) {
        close(fd);
        return IO_INVALID_HANDLE;
    }

    int backlog = 32;
    if (listen(fd, backlog)) {
        close(fd);
        return IO_INVALID_HANDLE;
    }

    op->handle = fd;
    op->user = user;
    return (io_handle) fd;
}

#endif
