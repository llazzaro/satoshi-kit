"""Tests for crypto/base58.py."""

from satoshi_kit.crypto.base58 import (
    b58decode,
    b58encode,
    decode_base58check,
    encode_base58check,
)


def test_b58encode_leading_zeros():
    # Leading 0x00 bytes become leading '1' characters
    assert b58encode(b"\x00\x00\x01") == "112"


def test_b58encode_decode_roundtrip():
    data = b"\x00" * 3 + b"\xff" * 10
    encoded = b58encode(data)
    decoded = b58decode(encoded)
    assert decoded == data


def test_b58decode_with_length():
    encoded = b58encode(b"\x00" * 25)
    assert b58decode(encoded, 25) == b"\x00" * 25
    assert b58decode(encoded, 10) is None  # wrong length


def test_base58check_roundtrip():
    payload = b"\x00" + b"\x01" * 20
    encoded = encode_base58check(payload)
    decoded = decode_base58check(encoded)
    assert decoded == payload


def test_base58check_bad_checksum():
    payload = b"\x00" + b"\x01" * 20
    encoded = encode_base58check(payload)
    # Corrupt last character
    bad = encoded[:-1] + ("1" if encoded[-1] != "1" else "2")
    assert decode_base58check(bad) is None
