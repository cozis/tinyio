
#define IO_VERSION_MAJOR 0
#define IO_VERSION_MINOR 0

# ifdef _WIN32
#   define IO_PLATFORM_WINDOWS 1
#   define IO_PLATFORM_LINUX   0
#   define IO_PLATFORM_OTHER   0
# elif __linux__
#   define IO_PLATFORM_WINDOWS 0
#   define IO_PLATFORM_LINUX   1
#   define IO_PLATFORM_OTHER   0
# else
#   define IO_PLATFORM_WINDOWS 0
#   define IO_PLATFORM_LINUX   0
#   define IO_PLATFORM_OTHER   0
# endif

#include <stdint.h>
#include <stdbool.h>

#if IO_PLATFORM_LINUX
#include <stdatomic.h>
#include <linux/io_uring.h>
#endif

/*
 * The OS handle type.
 */
#if IO_PLATFORM_LINUX
typedef int io_handle;
#define IO_INVALID_HANDLE -1
#elif IO_PLATFORM_WINDOWS
typedef void *io_handle;
#define IO_INVALID_HANDLE ((void*) -1)
#endif

/*
 * Windows calls this structure OVERLAPPED
 */
#if IO_PLATFORM_WINDOWS
struct io_overlap {
    unsigned long *internal;
    unsigned long *internal_high;
    union {
        struct {
            unsigned long offset;
            unsigned long offset_high;
        };
        void *pointer;
    };
    void *event;
};
#endif

enum io_optype {
    IO_VOID,
    IO_RECV,
    IO_SEND,
    IO_ACCEPT,
};

struct io_operation {
    enum io_optype type; // =IO_VOID when the struct is unused
    void *user;

    #if IO_PLATFORM_WINDOWS
    struct io_overlap ov;
    #endif
};

/*
 * io_uring's input queue
 */
#if IO_PLATFORM_LINUX
struct io_submission_queue {
    _Atomic unsigned int *head;
    _Atomic unsigned int *tail;
    unsigned int *mask;
    unsigned int *array;
    unsigned int limit;
    struct io_uring_sqe *entries;
};
#endif

/*
 * io_uring's output queue
 */
#if IO_PLATFORM_LINUX
struct io_completion_queue {
    _Atomic unsigned int *head;
    _Atomic unsigned int *tail;
    unsigned int *mask;
    unsigned int limit;
    struct io_uring_cqe *entries;
};
#endif

struct io_context {

    io_handle handle;
    uint32_t max_ops;
    struct io_operation *ops;

    #if IO_PLATFORM_LINUX
    struct io_submission_queue submissions;
    struct io_completion_queue completions;
    #endif
};

struct io_event {
    bool error;
    void *user;
    enum io_optype type;

    /*
     * Operation-specific results
     */
    union {
        uint32_t num;     // recv, send
        io_handle handle; // accept
    };
};

/*
 * Initialize an I/O context
 */
bool io_context_init(struct io_context *ioc,
                     struct io_operation *ops,
                     uint32_t max_ops);

/*
 * Deinitialize an I/O context. This will not close any previously
 * created handles.
 */
void io_context_free(struct io_context *ioc);

/*
 * Start an asynchronous receive operation on the handle. 
 * Only one pending receive operation per handle is supported.
 * 
 * When the operation completes, one of the following calls to
 * "io_wait" will return a completion event associated to this
 * recv. The "num" field of the event will hold the number of
 * bytes actually written from "dst". 
 */
bool io_start_recv(struct io_context *ioc, io_handle handle,
                   void *dst, uint32_t max, void *user);

/*
 * Works like "io_start_recv" but for sending.
 */
bool io_start_send(struct io_context *ioc, io_handle handle,
                   void *src, uint32_t num, void *user);


bool io_start_accept(struct io_context *ioc, io_handle handle,
                     void *user);

/*
 * Wait for the completion of an I/O event.
 */
void io_wait(struct io_context *ioc,
             struct io_event *ev);

io_handle io_open_file(struct io_context *ioc,
                       const char *name, int flags);

io_handle io_create_file(struct io_context *ioc,
                         const char *name, int flags);

io_handle io_listen(struct io_context *ioc,
                    const char *addr, int port);