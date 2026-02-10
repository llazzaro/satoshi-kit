"""Base58 and Base58Check encoding/decoding for Bitcoin."""

from __future__ import annotations

from satoshi_kit.crypto.hashing import double_sha256

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_BASE = len(_B58_ALPHABET)


def b58encode(data: bytes) -> str:
    """Encode bytes to a Base58 string.

    Leading zero bytes become leading '1' characters.
    """
    long_value = int.from_bytes(data, "big")

    result = ""
    while long_value > 0:
        long_value, mod = divmod(long_value, _B58_BASE)
        result = _B58_ALPHABET[mod] + result

    # Leading zero bytes → leading '1's
    n_pad = 0
    for byte in data:
        if byte == 0:
            n_pad += 1
        else:
            break

    return _B58_ALPHABET[0] * n_pad + result


def b58decode(v: str, length: int | None = None) -> bytes | None:
    """Decode a Base58 string to bytes.

    If *length* is given and the result doesn't match, returns ``None``.
    """
    long_value = 0
    for c in v:
        idx = _B58_ALPHABET.find(c)
        if idx < 0:
            raise ValueError(f"Invalid Base58 character: {c!r}")
        long_value = long_value * _B58_BASE + idx

    # Convert to bytes
    result = b""
    tmp = long_value
    while tmp > 0:
        tmp, mod = divmod(tmp, 256)
        result = bytes([mod]) + result

    # Leading '1's → leading 0x00 bytes
    n_pad = 0
    for c in v:
        if c == _B58_ALPHABET[0]:
            n_pad += 1
        else:
            break

    result = b"\x00" * n_pad + result

    if length is not None and len(result) != length:
        return None

    return result


def encode_base58check(payload: bytes) -> str:
    """Encode payload with a 4-byte double-SHA256 checksum appended."""
    checksum = double_sha256(payload)[:4]
    return b58encode(payload + checksum)


def decode_base58check(encoded: str) -> bytes | None:
    """Decode a Base58Check string; returns ``None`` if checksum fails."""
    decoded = b58decode(encoded)
    if decoded is None or len(decoded) < 5:
        return None

    payload = decoded[:-4]
    checksum = decoded[-4:]
    if double_sha256(payload)[:4] != checksum:
        return None

    return payload
