"""Tests for keys/ec.py."""

from satoshi_kit.keys.ec import ECKey


def test_from_secret_exponent_1():
    ec = ECKey.from_secret_exponent(1)
    secret = ec.secret_bytes()
    assert secret == b"\x00" * 31 + b"\x01"


def test_public_key_uncompressed():
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=False)
    assert len(pub) == 65
    assert pub[0] == 0x04


def test_public_key_compressed():
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=True)
    assert len(pub) == 33
    assert pub[0] in (0x02, 0x03)


def test_generate_random():
    ec = ECKey.generate()
    assert len(ec.secret_bytes()) == 32
    pub = ec.public_key(compressed=True)
    assert len(pub) == 33


def test_der_private_key():
    ec = ECKey.from_secret_exponent(1)
    der = ec.der_private_key(compressed=False)
    assert len(der) > 0
    # DER for uncompressed starts with 308201130201010420
    assert der[:8] == bytes.fromhex("3082011302010104")

    der_c = ec.der_private_key(compressed=True)
    assert len(der_c) > 0
    assert len(der_c) < len(der)  # compressed is shorter
