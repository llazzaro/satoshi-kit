"""Tests for crypto/hashing.py."""

from satoshi_kit.crypto.hashing import double_sha256, hash_160, keccak256


def test_double_sha256_empty():
    result = double_sha256(b"")
    assert result.hex() == "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"


def test_double_sha256_hello():
    result = double_sha256(b"hello")
    assert len(result) == 32


def test_hash_160():
    # SHA256 then RIPEMD160
    result = hash_160(b"\x04" + b"\x00" * 64)
    assert len(result) == 20


def test_keccak256_empty():
    """Keccak-256 of empty string — NOT the same as NIST SHA3-256."""
    result = keccak256(b"")
    # Original Keccak-256 of "" is c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    assert result.hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_keccak256_not_sha3():
    """Verify our Keccak is NOT NIST SHA3-256 (they differ in padding)."""
    import hashlib

    data = b"test"
    keccak_result = keccak256(data)
    sha3_result = hashlib.sha3_256(data).digest()
    # They MUST differ
    assert keccak_result != sha3_result
