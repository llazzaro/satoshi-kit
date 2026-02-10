"""Tests for keys/wif.py."""

import pytest

from satoshi_kit.keys.wif import secret_to_wif, wif_to_secret
from satoshi_kit.network import BITCOIN


def test_wif_roundtrip_uncompressed():
    secret = b"\x00" * 31 + b"\x01"
    wif = secret_to_wif(secret, compressed=False, network=BITCOIN)
    recovered, compressed = wif_to_secret(wif, network=BITCOIN)
    assert recovered == secret
    assert not compressed


def test_wif_roundtrip_compressed():
    secret = b"\x00" * 31 + b"\x01"
    wif = secret_to_wif(secret, compressed=True, network=BITCOIN)
    recovered, compressed = wif_to_secret(wif, network=BITCOIN)
    assert recovered == secret
    assert compressed


def test_known_wif():
    # Private key 1, uncompressed
    secret = b"\x00" * 31 + b"\x01"
    wif = secret_to_wif(secret, compressed=False, network=BITCOIN)
    assert wif == "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"


def test_wif_bad_checksum():
    with pytest.raises(ValueError, match="checksum"):
        wif_to_secret("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDX")
