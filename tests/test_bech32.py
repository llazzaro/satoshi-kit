"""Tests for crypto/bech32.py."""

from satoshi_kit.crypto.bech32 import bech32_encode


def test_bech32_encode_mainnet():
    # Test vector: 20-byte zero witness program on mainnet
    witprog = bytes(20)
    addr = bech32_encode("bc", 0, witprog)
    assert addr.startswith("bc1")
    assert len(addr) == 42


def test_bech32_encode_testnet():
    witprog = bytes(20)
    addr = bech32_encode("tb", 0, witprog)
    assert addr.startswith("tb1")
