"""Tests for hd/bip39.py."""

from satoshi_kit.hd.bip39 import Mnemonic


def test_generate_12_words():
    m = Mnemonic()
    mnemonic = m.generate(128)
    words = mnemonic.split(" ")
    assert len(words) == 12


def test_generate_24_words():
    m = Mnemonic()
    mnemonic = m.generate(256)
    words = mnemonic.split(" ")
    assert len(words) == 24


def test_check_valid():
    m = Mnemonic()
    assert m.check("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")


def test_check_invalid():
    m = Mnemonic()
    assert not m.check("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon")


def test_to_seed_trezor_vector():
    """BIP-39 test vector: 'abandon...about' + 'TREZOR' passphrase."""
    seed = Mnemonic.to_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "TREZOR",
    )
    assert len(seed) == 64
    assert seed.hex() == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"


def test_roundtrip_entropy():
    m = Mnemonic()
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    entropy = m.to_entropy(mnemonic)
    regenerated = m.to_mnemonic(bytes(entropy))
    assert regenerated == mnemonic
