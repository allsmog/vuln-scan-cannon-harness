"""Tiny fixed-buffer parser — a stand-in for a memory-safety bug.

Reads an input file into a 16-byte buffer with no bounds check. An input longer
than 16 bytes overflows the buffer (IndexError). For cannon's dynamic detector
to PROVE the bug, it must craft an input > 16 bytes and reproduce the crash.
"""
import sys


def main():
    data = open(sys.argv[1], "rb").read()
    buf = bytearray(16)
    for i, b in enumerate(data):
        buf[i] = b  # BUG: no bounds check — overflows when i >= 16
    print("parsed ok:", len(data), "bytes")


if __name__ == "__main__":
    main()
