all:
	gcc example.c  io2.c -o example  -Wall -Wextra -ggdb
	gcc example2.c io2.c -o example2 -Wall -Wextra -ggdb

clean:
	rm example example.exe
