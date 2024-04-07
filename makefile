all:
	gcc example.c io.c -o example -Wall -Wextra -ggdb

clean:
	rm example example.exe