"""Tests for keys/address.py."""

from satoshi_kit.keys.address import (
    eip55_checksum,
    pubkey_to_bech32_address,
    pubkey_to_ethereum_address,
    pubkey_to_p2pkh_address,
    pubkey_to_p2sh_p2wpkh_address,
)
from satoshi_kit.keys.ec import ECKey
from satoshi_kit.network import BITCOIN


def test_p2pkh_address_key_1():
    """Private key = 1, uncompressed → known address."""
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=False)
    addr = pubkey_to_p2pkh_address(pub, BITCOIN)
    assert addr == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"


def test_p2pkh_address_key_1_compressed():
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=True)
    addr = pubkey_to_p2pkh_address(pub, BITCOIN)
    assert addr == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"


def test_p2sh_p2wpkh_address():
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=True)
    addr = pubkey_to_p2sh_p2wpkh_address(pub, BITCOIN)
    assert addr.startswith("3")


def test_bech32_address():
    ec = ECKey.from_secret_exponent(1)
    pub = ec.public_key(compressed=True)
    addr = pubkey_to_bech32_address(pub, BITCOIN)
    assert addr.startswith("bc1")


def test_eip55_checksum():
    """Test vector from EIP-55."""
    assert eip55_checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"


def test_pubkey_to_ethereum_address():
    ec = ECKey.from_secret_exponent(1)
    pub_uncompressed = ec.public_key(compressed=False)
    eth_addr = pubkey_to_ethereum_address(pub_uncompressed)
    assert eth_addr.startswith("0x")
    assert len(eth_addr) == 42
