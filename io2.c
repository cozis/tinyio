#include "io2.h"

#include <stdint.h>

#if IO_PLATFORM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#endif

bool io_global_init(void)
{
    #if IO_PLATFORM_WINDOWS
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) != NO_ERROR;
    #endif

    #if IO_PLATFORM_LINUX
    return true;
    #endif
}

void io_global_free(void)
{
    #if IO_PLATFORM_WINDOWS
    WSACleanup();
    #endif
}

#if IO_PLATFORM_WINDOWS
bool io_init_windows(struct io_context *ioc)
{
    io_os_handle os_handle = CreateIoCompletionPort(IO_INVALID_HANDLE, NULL, 0, 1);
    if (os_handle == INVALID_HANDLE_VALUE)
        return false;
    
    ioc->os_handle = os_handle;
    return true;
}
#endif

#if IO_PLATFORM_WINDOWS
void io_free_windows(struct io_context *ioc)
{
    CloseHandle(ioc->os_handle);
}
#endif

#if IO_PLATFORM_LINUX
bool io_init_linux(struct io_context *ioc)
{
    
    struct io_uring_params p;
    void *sq_ptr, *cq_ptr;
    /* See io_uring_setup(2) for io_uring_params.flags you can set */
    memset(&p, 0, sizeof(p));
    int fd = io_uring_setup(32, &p);
    if (fd < 0)
        return false;

    ioc->os_handle = fd;

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
#endif

#if IO_PLATFORM_LINUX
void io_free_linux(struct io_context *ioc)
{
    close(ioc->os_handle);
}
#endif

#if IO_PLATFORM_LINUX
static bool start_uring_op(struct io_context *ioc,
                           struct io_uring_sqe sqe)
{
    // TODO
    return false;
}
#endif

static void clear_res(struct io_resource *res)
{
    res->type = IO_RES_VOID;
    res->pending = 0;

    #if IO_PLATFORM_WINDOWS
    res->os_handle = INVALID_HANDLE_VALUE;
    #endif

    #if IO_PLATFORM_LINUX
    res->os_handle = -1;
    #endif
}

bool io_init(struct io_context   *ioc,
             struct io_resource  *res,
             struct io_operation *ops,
             uint16_t max_res,
             uint16_t max_ops)
{
    ioc->res = res;
    ioc->ops = ops;
    ioc->max_res = max_res;
    ioc->max_ops = max_ops;

    for (uint16_t i = 0; i < max_res; i++) {
        res[i].gen = 0;
        clear_res(&res[i]);
    }
    
    for (uint16_t i = 0; i < max_ops; i++)
        ops[i].type = IO_VOID;

    #if IO_PLATFORM_WINDOWS
    return io_init_windows(ioc);
    #endif

    #if IO_PLATFORM_LINUX
    return io_init_linux(ioc);
    #endif
}

static void
close_internal(struct io_context  *ioc,
               struct io_resource *res)
{
    #if IO_PLATFORM_WINDOWS
    if (res->type == IO_RES_SOCKET)
        closesocket(res->os_handle);
    else
        CloseHandle(res->os_handle);
    #elif IO_PLATFORM_LINUX
    close(res->os_handle);
    #endif

    // Mark associated operation structures as unused
    for (uint16_t i = 0, marked = 0; marked < res->pending; i++) {
        strct io_operation *op;
        op = &ioc->ops[i];
        if (op->type != IO_VOID && op->res == res) {
            op->type = IO_VOID;
            op->res  = NULL;
            marked++;
        }
    }

    clear_res(res);

    res->gen++;
    if (res->gen == UINT16_MAX)
        res->gen = 0;
}

struct io_resource *res_from_handle(struct io_context *ioc,
                                    io_handle handle)
{
    if (handle == IO_INVALID)
        return NULL;

    static_assert(sizeof(uint32_t) == sizeof(io_handle));
    uint16_t idx = handle & 0xFFFF;
    uint16_t gen = handle >> 16;
    if (idx >= ioc->max_res)
        return NULL;

    struct io_resource *res = &ioc->res[idx];
    if (res->gen != gen)
        return NULL;
    
    return res;
}

static io_handle handle_from_res(struct io_context  *ioc,
                                 struct io_resource *res)
{
    io_handle handle;
    static_assert(sizeof(uint32_t) == sizeof(io_handle));

    uint32_t idx = res - ioc->res;
    uint32_t gen = res->gen;
    handle = idx | (gen << 16);

    assert(gen != UINT16_MAX);
    assert(handle != IO_INVALID);

    return handle;
}

void io_close(struct io_context *ioc,
              io_handle handle)
{
    struct io_resource *res;
    
    res = res_from_handle(handle);
    if (res == NULL)
        return;

    close_internal(ioc, res);
}

void io_free(struct io_context *ioc)
{
    for (uint16_t i = 0; i < ioc->max_res; i++)
        if (ioc->res[i].type != IO_RES_VOID)
            close_internal(ioc, &ioc->res[i]);

    #if IO_PLATFORM_WINDOWS
    io_free_windows(ioc);
    #endif

    #if IO_PLATFORM_WINDOWS
    io_free_linux(ioc);
    #endif
}

static struct io_operation*
find_unused_op(struct io_context *ioc)
{
    for (uint16_t i = 0; i < ioc->max_ops; i++) {
        struct io_operation *op = &ioc->ops[i];
        if (op->type == IO_VOID)
            return op;
    }
    return NULL;
}

#if IO_PLATFORM_LINUX
static bool io_recv_linux(struct io_context   *ioc,
                          struct io_resource  *res,
                          struct io_operation *op,
                          void *dst, uint32_t max)
{
    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_READ;
    sqe.fd   = (int) res->os_handle;
    sqe.addr = (uint64_t) dst;
    sqe.len  = max;
    sqe.user_data = (uint64_t) op;
    return start_uring_op(ioc, sqe);
}
#endif

#if IO_PLATFORM_LINUX
static bool io_send_linux(struct io_context   *ioc,
                          struct io_resource  *res,
                          struct io_operation *op,
                          void *src, uint32_t num)
{
    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_WRITE;
    sqe.fd   = (int) res->os_handle;
    sqe.addr = (uint64_t) sec;
    sqe.len  = num;
    sqe.user_data = (uint64_t) op;
    return start_uring_op(ioc, sqe);
}
#endif

#if IO_PLATFORM_LINUX
static bool io_accept_linux(struct io_context   *ioc,
                            struct io_resource  *res,
                            struct io_operation *op,
                            io_os_handle os_handle)
{
    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof(sqe));
    sqe.opcode = IORING_OP_ACCEPT;
    sqe.fd = (int) os_handle;
    sqe.user_data = (uint64_t) op;
    return start_uring_op(ioc, sqe);
}
#endif

#if IO_PLATFORM_WINDOWS
static bool io_recv_windows(struct io_context   *ioc,
                            struct io_resource  *res,
                            struct io_operation *op,
                            void *dst, uint32_t max)
{
    memset(&op->ov, 0, sizeof(struct io_os_overlap));
    int ok = ReadFile(res->os_handle, dst, max, NULL, &op->ov);
	if (!ok && GetLastError() != ERROR_IO_PENDING)
		return false;
    return true;
}
#endif

#if IO_PLATFORM_WINDOWS
static bool io_send_windows(struct io_context   *ioc,
                            struct io_resource  *res,
                            struct io_operation *op,
                            void *src, uint32_t num)
{
    memset(&op->ov, 0, sizeof(struct io_os_overlap));
    int ok = ReadFile(res->os_handle, src, num, NULL, &op->ov);
	if (!ok && GetLastError() != ERROR_IO_PENDING)
		return false;
    return true;
}
#endif

#if IO_PLATFORM_WINDOWS
static bool io_accept_windows(struct io_context   *ioc,
                              struct io_resource  *res,
                              struct io_operation *op,
                              io_os_handle os_handle)
{
    memset(&op->ov, 0, sizeof(struct io_os_overlap));
    
    SOCKET new_os_handle = socket(AF_INET, SOCK_STREAM, 0);
    if (new_os_handle == INVALID_HANDLE_VALUE)
        return false;

    LPFN_ACCEPTEX lpfnAcceptEx = NULL;
    GUID GuidAcceptEx = WSAID_ACCEPTEX;

    unsigned long num;
    int ret = WSAIoctl(res->os_handle,
             SIO_GET_EXTENSION_FUNCTION_POINTER,
             &GuidAcceptEx, sizeof(GuidAcceptEx), 
             &lpfnAcceptEx, sizeof(lpfnAcceptEx), 
             &num, NULL, NULL);
    if (ret == SOCKET_ERROR) {
        closesocket(new_os_handle);
        return false;
    }

    _Static_assert(IO_SOCKADDR_IN_SIZE == sizeof(struct sockaddr_in));

    int ok = lpfnAcceptEx(handle2, os_handle, op->accept_buffer,
                          sizeof(op->accept_buffer) - ((sizeof(struct sockaddr_in) + 16) * 2),
                          sizeof(struct sockaddr_in) + 16, 
                          sizeof(struct sockaddr_in) + 16,
                          &num, &op->ov);
    if (!ok) {
        closesocket(new_os_handle);
        return false;
    }

    op->accepted = new_os_handle;
    return true;
}
#endif


bool io_recv(struct io_context *ioc,
             void *user, io_handle handle,
             void *dst, uint32_t max)
{
    struct io_operation *op;
    struct io_resource *res;

    res = res_from_handle(ioc, handle);
    if (res == NULL)
        return false;
    
    op = find_unused_op(ioc);
    if (op == NULL)
        return false;

    enum io_optype type = IO_RECV;
    
    #if IO_PLATFORM_LINUX
    if (!io_recv_linux(ioc, res, op, dst, max))
        return false;
    #endif

    #if IO_PLATFORM_WINDOWS
    if (!io_recv_windows(ioc, res, op, dst, max))
        return false;
    #endif

    res->pending++;
    op->res = res;
    op->type = type;
    op->user = user;
    return true;
}

bool io_send(struct io_context *ioc,
             void *user, io_handle handle,
             void *src, uint32_t num)
{
    struct io_operation *op;
    struct io_resource *res;

    res = res_from_handle(ioc, handle);
    if (res == NULL)
        return false;
    
    op = find_unused_op(ioc);
    if (op == NULL)
        return false;

    enum io_optype type = IO_SEND;
    
    #if IO_PLATFORM_LINUX
    if (!io_send_linux(ioc, res, op, src, num))
        return false;
    #endif

    #if IO_PLATFORM_WINDOWS
    if (!io_send_windows(ioc, res, op, src, num))
        return false;
    #endif

    res->pending++;
    op->res = res;
    op->type = type;
    op->user = user;
    return true;
}

bool io_accept(struct io_context *ioc,
               void *user, io_handle handle)
{
    struct io_operation *op;
    struct io_resource *res;

    res = res_from_handle(ioc, handle);
    if (res == NULL)
        return false;
    
    op = find_unused_op(ioc);
    if (op == NULL)
        return false;

    enum io_optype type = IO_ACCEPT;

    #if IO_PLATFORM_LINUX
    if (!io_accept_linux(ioc, res, op, res->os_handle))
        return false;
    #endif

    #if IO_PLATFORM_WINDOWS
    if (!io_accept_windows(ioc, res, op, res->os_handle))
        return false;
    #endif

    res->pending++;
    op->res = res;
    op->type = type;
    op->user = user;
    return true;
}

static struct io_resource*
find_unused_res(struct io_context *ioc)
{
    for (uint16_t i = 0; i < ioc->max_res; i++) {
        struct io_resource *res = &ioc->res[i];
        if (res->type == IO_RES_VOID)
            return res;
    }
    return NULL;
}

#if IO_PLATFORM_WINDOWS
static io_os_handle
io_open_file_windows(struct io_context *ioc,
                     const char *file, int flags)
{
    unsigned long access = 0;
	if (flags & IO_ACCESS_RD) access |= GENERIC_READ;
	if (flags & IO_ACCESS_WR) access |= GENERIC_WRITE;

	io_os_handle os_handle = CreateFileA(file, access, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (os_handle == IO_INVALID_HANDLE)
		return IO_INVALID_HANDLE;

    if (CreateIoCompletionPort(os_handle, ioc->os_handle, NULL, 0) == NULL) {
		CloseHandle(os_handle);
		return IO_INVALID_HANDLE;
	}

    return os_handle;
}
#endif

#if IO_PLATFORM_LINUX
static io_os_handle
io_open_file_linux(struct io_context *ioc,
                   const char *file, int flags)
{
    int flags2 = 0;
	if (flags & IO_ACCESS_RD) flags2 |= O_RDONLY;
	if (flags & IO_ACCESS_WR) flags2 |= O_WRONLY;

	return open(name, flags2);
}
#endif

io_handle io_open_file(struct io_context *ioc,
                       const char *file, int flags)
{
    io_os_handle os_handle;
    struct io_resource *res;

    res = find_unused_res(ioc);
    if (res == NULL)
        return IO_INVALID;

    #if IO_PLATFORM_WINDOWS
    os_handle = io_open_file_windows(ioc, file, flags);
    if (os_handle == INVALID_HANDLE_VALUE)
        return IO_INVALID;
    #endif

    #if IO_PLATFORM_LINUX
    os_handle = io_open_file_linux(ioc, file, flags);
    if (os_handle < 0)
        return IO_INVALID;
    #endif

    res->type = IO_RES_FILE;
    res->pending = 0;
    res->os_handle = os_handle;
    return handle_from_res(ioc, res);
}

#if IO_PLATFORM_WINDOWS
static io_os_handle
io_create_file_windows(struct io_context *ioc,
                       const char *file, int flags)
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

	io_os_handle os_handle = CreateFileA(file, GENERIC_WRITE, 0, NULL, flags2, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (os_handle == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    if (CreateIoCompletionPort(handle, ioc->os_handle, NULL, 0) == NULL) {
		CloseHandle(os_handle);
		return INVALID_HANDLE_VALUE;
	}

    return handle;
}
#endif

#if IO_PLATFORM_LINUX
static io_os_handle
io_create_file_linux(struct io_context *ioc,
                     const char *file, int flags)
{
    int flags2 = O_CREAT | O_WRONLY;

	if (flags & IO_CREATE_CANTEXIST)
		flags2 |= O_EXCL;
	else {
		if (flags & IO_CREATE_OVERWRITE)
			flags2 |= O_TRUNC;
	}

    // TODO: is 0666 ok?
	return open(name, flags2, 0666);
}
#endif

io_handle io_create_file(struct io_context *ioc,
                         const char *file, int flags)
{
    io_os_handle os_handle;
    struct io_resource *res;

    res = find_unused_res(ioc);
    if (res == NULL)
        return IO_INVALID;

    #if IO_PLATFORM_WINDOWS
    os_handle = io_create_file_windows(ioc, file, flags);
    if (os_handle == INVALID_HANDLE_VALUE)
        return IO_INVALID;
    #endif

    #if IO_PLATFORM_LINUX
    os_handle = io_create_file_linux(ioc, file, flags);
    if (os_handle < 0)
        return IO_INVALID;
    #endif

    res->type = IO_RES_FILE;
    res->pending = 0;
    res->os_handle = os_handle;
    return handle_from_res(ioc, res);
}

io_handle io_start_server(struct io_context *ioc,
                          const char *addr, int port)
{
    if (port < 1 || port > UINT16_MAX)
        return IO_INVALID;

    struct in_addr addr2;
    if (addr == NULL)
        addr2.s_addr = INADDR_ANY;
    else {
        if (1 != inet_pton(AF_INET, addr, &addr2))
            return IO_INVALID;
    }

    io_os_handle os_handle;
    struct io_resource *res;

    res = find_unused_res(ioc);
    if (res == NULL)
        return IO_INVALID;

    os_handle = socket(AF_INET, SOCK_STREAM, 0);

    #if IO_PLATFORM_LINUX
    if (os_handle < 0)
        return IO_INVALID;
    #endif

    #if IO_PLATFORM_WINDOWS
    if (os_handle == INVALID_HANDLE_VALUE)
        return IO_INVALID;
    #endif

    int one = 1;
    setsockopt(os_handle, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in buf;
    buf.sin_family = AF_INET;
    buf.sin_port = htons(port);
    buf.sin_addr = addr2;
    if (bind(os_handle, (struct sockaddr*) &buf, sizeof(buf))) {
        close(os_handle);
        return IO_INVALID;
    }

    int backlog = 32;
    if (listen(os_handle, backlog)) {
        close(os_handle);
        return IO_INVALID;
    }

    res->type = IO_RES_SOCKET;
    res->pending = 0;
    res->os_handle = os_handle;
    return handle_from_res(ioc, res);
}

#if IO_PLATFORM_WINDOWS

static unsigned long
convert_timeout(int timeout)
{
    if (timeout < 0)
        return ~0U;
    else
        return timeout;
}

static struct io_operation*
op_from_ov(struct io_os_overlap *ov)
{
    return (struct io_operation*) ((char*) ov - offsetof(struct io_operation, ov));
}

#endif

#if IO_PLATFORM_WINDOWS
static void
io_wait_windows(struct io_context *ioc,
                struct io_event *ev)
{
    void *unused;
	struct io_os_overlap *ov;
    unsigned long num;
	int ok = GetQueuedCompletionStatus(ioc->os_handle, &num, &unused, &ov, convert_timeout(-1));

    if (!ok) {

        if (ov == NULL) {

            /*
             * General failure
             */
            
            ev->evtype = IO_ERROR;
            ev->optype = IO_VOID;
            ev->handle = IO_INVALID;
            ev->user   = NULL;

        } else {

            /*
             * Operation failure
             */

            struct io_operation *op = op_from_ov(ov);
            struct io_resource *res = op->res;

            ev->evtype = IO_ABORT;
            ev->optype = op->type;
            ev->handle = handle_from_res(ioc, res);
            ev->user   = op->user;

            if (op->type == IO_ACCEPT)
                closesocket(op->accepted);

            op->type = IO_VOID; // Mark unused

            assert(res->pending > 0);
            res->pending--;
        }
        return;
    }

    struct io_operation *op = op_from_ov(ov);
    struct io_resource *res = op->res;

    ev->evtype = IO_COMPLETE;
    ev->optype = op->type;
    ev->handle = handle_from_res(ioc, res);
    ev->user   = op->user;

    switch (op->type) {

        case IO_RECV:
        case IO_SEND:
        ev->num = num;
        break;

        case IO_ACCEPT:
        {
            struct io_resource *res2;

            res2 = find_unused_res(ioc);
            if (res2 == NULL) {

                closesocket(op->accepted);

                ev->evtype = IO_ABORT;
                ev->optype = IO_ACCEPT;
                ev->handle = handle_from_res(ioc, res);
                ev->user   = op->user;
    
                assert(res->pending > 0);
                res->pending--;
                op->type = IO_VOID;
                return;
            }

            res2->type = IO_RES_SOCKET;
            res2->pending = 0;
            res2->os_handle = op->accepted;

            ev->accepted = handle_from_res(ioc, res2);
        }
        break;

        default:
        break;
    }

    assert(res->pending > 0);
    res->pending--;

    op->type = IO_VOID; // Mark unused
}
#endif

#if IO_PLATFORM_LINUX
static void
io_wait_linux(struct io_context *ioc,
              struct io_event *ev)
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
            ev->evtype = IO_ERROR;
            ev->optype = IO_VOID;
            ev->handle = IO_INVALID;
            ev->user   = NULL;
            return;
        }
    }

    struct io_uring_cqe *cqe;
    struct io_operation *op;
    struct io_resource *res;

    cqe = &ioc->completions.entries[head & (*ioc->completions.mask)];

    op = (void*) cqe->user_data;
    res = op->res;

    ev->user = op->user;
    ev->handle = handle_from_res(ioc, op->res);
    ev->optype = op->type;

    if (cqe->res < 0)
        ev->evtype = IO_ABORT;
    else {
        ev->evtype = IO_COMPLETE;
        switch (op->type) {
            case IO_RECV: ev->num = cqe->res; break;
            case IO_SEND: ev->num = cqe->res; break;
            case IO_ACCEPT: ev->accepted = cqe->res; break;
            default:break;
        }
    }

    assert(res->pending > 0);
    res->pending--;
    op->type = IO_VOID; // Mark unused

    /* --- write barrier --- */
    atomic_store(ioc->completions.head, head+1);
}
#endif

void io_wait(struct io_context *ioc,
             struct io_event *ev)
{
    #if IO_PLATFORM_WINDOWS
    io_wait_windows(ioc, ev);
    #endif

    #if IO_PLATFORM_LINUX
    io_wait_linux(ioc, ev);
    #endif
}
