
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
typedef int io_raw_handle;
#elif IO_PLATFORM_WINDOWS
typedef void *io_raw_handle;
#endif

typedef uint16_t io_handle;

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

enum io_resource_type {
    IO_RES_VOID,
    IO_RES_FILE,
    IO_RES_SOCKET,
};

struct io_resource {
    enum io_resource_type type;
    io_raw_handle raw_handle;
    uint16_t headop;
};

enum io_optype {
    IO_VOID,
    IO_RECV,
    IO_SEND,
    IO_ACCEPT,
};

#define IO_SOCKADDR_IN_SIZE 16

struct io_operation {

    io_handle handle;
    uint16_t  nextop;

    enum io_optype type;
    void          *user;

    #if IO_PLATFORM_WINDOWS
    io_raw_handle accept_handle;
    struct io_overlap ov;
    char accept_buffer[2 * (IO_SOCKADDR_IN_SIZE + 16)];
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

    io_raw_handle raw_handle;
    uint16_t max_ops;
    uint16_t max_res;
    struct io_operation *ops;
    struct io_resource  *res;

    #if IO_PLATFORM_LINUX
    struct io_submission_queue submissions;
    struct io_completion_queue completions;
    #endif
};

struct io_event {
    bool error;
    void *user;
    enum io_optype type;
    io_handle handle;

    /*
     * Operation-specific results
     */
    union {
        uint32_t num;     // recv, send
        io_handle handle; // accept
    } data;
};


bool io_global_init(void);

void io_global_free(void);

/*
 * Initialize an I/O context
 */
bool io_context_init(struct io_context *ioc,
                     struct io_resource *res,
                     struct io_operation *ops,
                     uint16_t max_res,
                     uint16_t max_ops);

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
                   void *dst, uint32_t max);

/*
 * Works like "io_start_recv" but for sending.
 */
bool io_start_send(struct io_context *ioc, io_handle handle,
                   void *src, uint32_t num);


bool io_start_accept(struct io_context *ioc, io_handle handle);

/*
 * Wait for the completion of an I/O event.
 */
void io_wait(struct io_context *ioc,
             struct io_event *ev);

/*
 * Flags for "io_open_file" and "io_create_file"
 */
enum {
    IO_ACCESS_RD = 1 << 0,
    IO_ACCESS_WR = 1 << 1,
    IO_CREATE_OVERWRITE = 1 << 2,
    IO_CREATE_CANTEXIST = 1 << 3,
};

io_handle io_open_file(struct io_context *ioc,
                       const char *name, int flags,
                       void *user);

io_handle io_create_file(struct io_context *ioc,
                         const char *name, int flags,
                         void *user);

io_handle io_listen(struct io_context *ioc,
                    const char *addr, int port,
                    void *user);

void io_close(struct io_context *ioc,
              io_handle handle);