
#define IO_VERSION_MAJOR 0
#define IO_VERSION_MINOR 0

#ifdef _WIN32
#   define IO_PLATFORM_WINDOWS 1
#   define IO_PLATFORM_LINUX   0
#   define IO_PLATFORM_OTHER   0
#elif __linux__
#   define IO_PLATFORM_WINDOWS 0
#   define IO_PLATFORM_LINUX   1
#   define IO_PLATFORM_OTHER   0
#else
#   define IO_PLATFORM_WINDOWS 0
#   define IO_PLATFORM_LINUX   0
#   define IO_PLATFORM_OTHER   0
#endif

#if IO_PLATFORM_WINDOWS
typedef void *io_os_handle;
#endif

#if IO_PLATFORM_LINUX
typedef int io_os_handle;
#endif

typedef uint32_t io_handle;
#define IO_INVALID ((uint32_t) -1)

struct io_os_overlap {
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
}:

enum io_optype {
    IO_VOID,
    IO_RECV,
    IO_SEND,
    IO_ACCEPT,
};

#define IO_SOCKADDR_IN_SIZE 16

struct io_operation {

    enum io_optype type;
    struct io_resource *res;
    void *user;

    #if IO_PLATFORM_WINDOWS
    struct io_os_handle accepted;
    struct io_os_overlap ov;
    char accept_buffer[2 * (IO_SOCKADDR_IN_SIZE + 16)];
    #endif
};

enum io_restype {
    IO_RES_VOID,
    IO_RES_FILE,
    IO_RES_SOCKET,
};

struct io_resource {
    enum io_restype type;
    io_os_handle os_handle;
    uint16_t pending;
};

struct io_context {
    io_os_handle os_handle;
    uint16_t max_res;
    uint16_t max_ops;
    struct io_resource *res;
    struct io_operation *ops;
};

enum io_evtype {
    IO_ERROR,
    IO_ABORT,
    IO_COMPLETE,
};

struct io_event {
    enum io_evtype evtype;
    enum io_optype optype;
    io_handle handle;
    void *user;

    union {
        uint32_t num;
        io_handle accepted;
    };
};

bool io_global_init(void);
void io_global_free(void);

bool io_init(struct io_context   *ioc,
             struct io_resource  *res,
             struct io_operation *ops,
             uint16_t max_res,
             uint16_t max_ops);

void io_free(struct io_context *ioc);

void io_wait(struct io_context *ioc,
             struct io_event *ev);

bool io_recv(struct io_context *ioc,
             void *user, io_handle handle,
             void *dsc, uint32_t max);

bool io_send(struct io_context *ioc,
             void *user, io_handle handle,
             void *src, uint32_t num);

bool io_accept(struct io_context *ioc,
               void *user, io_handle handle);

void io_close(struct io_context *ioc,
              io_handle handle);

/*
 * Flags for io_open_file and io_create_file
 */
enum {
    IO_ACCESS_RD = 1 << 0,
    IO_ACCESS_WR = 1 << 1,
    IO_CREATE_OVERWRITE = 1 << 2,
    IO_CREATE_CANTEXIST = 1 << 3,
};

io_handle io_open_file(struct io_context *ioc,
                       const char *file, int flags);

io_handle io_create_file(struct io_context *ioc,
                         const char *file, int flags);

io_handle io_start_server(struct io_context *ioc,
                          const char *addr, int port);