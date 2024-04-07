all:
	gcc example.c io_win.c io_linux.c -o example -Wall -Wextra -ggdb