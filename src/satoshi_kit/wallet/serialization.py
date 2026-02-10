"""Bitcoin binary serialization (BCDataStream)."""

from __future__ import annotations

import struct


class SerializationError(Exception):
    """Raised on serialization/deserialization failures."""


class BCDataStream:
    """Bitcoin Core data stream for reading/writing binary wallet data."""

    def __init__(self, data: bytes | None = None) -> None:
        self.input: bytes = data or b""
        self.read_cursor: int = 0

    def clear(self) -> None:
        self.input = b""
        self.read_cursor = 0

    def write(self, data: bytes) -> None:
        self.input += data

    def read_string(self) -> bytes:
        """Read a compact-size-prefixed string."""
        if not self.input:
            raise SerializationError("call write(bytes) before trying to deserialize")
        length = self.read_compact_size()
        return self.read_bytes(length)

    def write_string(self, string: bytes) -> None:
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length: int) -> bytes:
        try:
            result = self.input[self.read_cursor : self.read_cursor + length]
            self.read_cursor += length
            return result
        except IndexError as exc:
            raise SerializationError("attempt to read past end of buffer") from exc

    def read_boolean(self) -> bool:
        return self.read_bytes(1)[0] != 0

    def read_int16(self) -> int:
        return self._read_num("<h")

    def read_uint16(self) -> int:
        return self._read_num("<H")

    def read_int32(self) -> int:
        return self._read_num("<i")

    def read_uint32(self) -> int:
        return self._read_num("<I")

    def read_int64(self) -> int:
        return self._read_num("<q")

    def read_uint64(self) -> int:
        return self._read_num("<Q")

    def write_boolean(self, val: bool) -> None:
        self.write(bytes([int(val)]))

    def write_int16(self, val: int) -> None:
        self._write_num("<h", val)

    def write_uint16(self, val: int) -> None:
        self._write_num("<H", val)

    def write_int32(self, val: int) -> None:
        self._write_num("<i", val)

    def write_uint32(self, val: int) -> None:
        self._write_num("<I", val)

    def write_int64(self, val: int) -> None:
        self._write_num("<q", val)

    def write_uint64(self, val: int) -> None:
        self._write_num("<Q", val)

    def read_compact_size(self) -> int:
        size = self.input[self.read_cursor]
        self.read_cursor += 1
        if size == 253:
            size = self._read_num("<H")
        elif size == 254:
            size = self._read_num("<I")
        elif size == 255:
            size = self._read_num("<Q")
        return size

    def write_compact_size(self, size: int) -> None:
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(bytes([size]))
        elif size < 2**16:
            self.write(b"\xfd")
            self._write_num("<H", size)
        elif size < 2**32:
            self.write(b"\xfe")
            self._write_num("<I", size)
        elif size < 2**64:
            self.write(b"\xff")
            self._write_num("<Q", size)

    def _read_num(self, fmt: str) -> int:
        (i,) = struct.unpack_from(fmt, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(fmt)
        return int(i)

    def _write_num(self, fmt: str, num: int) -> None:
        self.write(struct.pack(fmt, num))
