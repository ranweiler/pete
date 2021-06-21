#!/usr/bin/env python3
import re
import sys


def main():
    for line in sys.stdin:
        m = parse_line(line.strip())

        if m:
            pid, stop_type, syscallno = m
            print(f"{pid}\t{stop_type}\t{syscallno}")


PATTERN = re.compile("(\d+) .* raw_syscalls:sys_(enter|exit): NR (\d+)")


def parse_line(line):
    m = PATTERN.search(line)

    if not m:
        return None

    # PID, enter/exit, syscall number.
    return m.group(1, 2, 3)


if __name__ == "__main__":
    main()
