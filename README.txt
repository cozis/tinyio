=== TinyIO ===

TinyIO is a cross-platform (Windows and Linux) API for asynchronous I/O operations. It's backed by io_uring on Linux and I/O completion ports (IOCP) on Windows. It has no dependencies (other than OS stuff and freestanding libc headers) and does no dynamic allocations. To use it, you need to add io.c and io.h in your source tree and compile them as they were your own files.

<<< WARNING >>> It's likely that the io_uring code has some bugs, so be wary! Also bug reports are appreciated :)

It's released in the public domain, so you can just adapt the code for your own projects. Pull requests would be appreciated though.