CC = clang-11
CFLAGS = -fno-pie

all: nop.exe

nop.exe: nop.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -rf *.exe *.o
