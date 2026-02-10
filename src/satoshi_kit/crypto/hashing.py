"""Cryptographic hash functions for Bitcoin and Ethereum."""

from __future__ import annotations

import hashlib

from Crypto.Hash import keccak as _keccak  # pycryptodome: original Keccak (NOT NIST SHA3)


def hash_160(data: bytes) -> bytes:
    """RIPEMD-160(SHA-256(data)) — used for Bitcoin address generation."""
    md = hashlib.new("ripemd160")
    md.update(hashlib.sha256(data).digest())
    return md.digest()


def double_sha256(data: bytes) -> bytes:
    """SHA-256(SHA-256(data)) — Bitcoin's standard double hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 hash (NOT NIST SHA3-256).

    Ethereum uses the original Keccak with padding byte 0x01,
    which differs from NIST SHA3-256 (padding byte 0x06).
    """
    k = _keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()
