
This repository implements a cross-platform (Windows and Linux) API for asynchronous I/O operations. It's backed by io_uring on Linux and I/O completion ports (IOCP) on windows. It has no dependencies (other than OS stuff and freestanding libc headers) and does no dynamic allocations.

It's likely that the io_uring code has some bugs, so be wary! Also bug reports are appreciated :)

To use it, you need to add io_linux.c and io_win.c in your source tree and compile them as they were your files. Each .c file is ignored when not compiling for its platform, so you can include them both in all builds.
