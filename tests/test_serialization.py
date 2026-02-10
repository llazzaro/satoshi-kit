"""Tests for wallet/serialization.py."""

from satoshi_kit.wallet.serialization import BCDataStream


def test_string_roundtrip():
    ds = BCDataStream()
    ds.write_string(b"hello")
    ds2 = BCDataStream(ds.input)
    assert ds2.read_string() == b"hello"


def test_int32_roundtrip():
    ds = BCDataStream()
    ds.write_int32(-42)
    ds2 = BCDataStream(ds.input)
    assert ds2.read_int32() == -42


def test_uint32_roundtrip():
    ds = BCDataStream()
    ds.write_uint32(80100)
    ds2 = BCDataStream(ds.input)
    assert ds2.read_uint32() == 80100


def test_compact_size_small():
    ds = BCDataStream()
    ds.write_compact_size(100)
    ds2 = BCDataStream(ds.input)
    assert ds2.read_compact_size() == 100


def test_compact_size_medium():
    ds = BCDataStream()
    ds.write_compact_size(300)
    ds2 = BCDataStream(ds.input)
    assert ds2.read_compact_size() == 300


def test_compact_size_large():
    ds = BCDataStream()
    ds.write_compact_size(70000)
    ds2 = BCDataStream(ds.input)
    assert ds2.read_compact_size() == 70000


def test_int64_roundtrip():
    ds = BCDataStream()
    ds.write_int64(1234567890123)
    ds2 = BCDataStream(ds.input)
    assert ds2.read_int64() == 1234567890123


def test_boolean_roundtrip():
    ds = BCDataStream()
    ds.write_boolean(True)
    ds.write_boolean(False)
    ds2 = BCDataStream(ds.input)
    assert ds2.read_boolean() is True
    assert ds2.read_boolean() is False
