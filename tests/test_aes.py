"""Tests for crypto/aes.py."""

from satoshi_kit.crypto.aes import aes_cbc_decrypt, aes_cbc_encrypt, derive_key_iv


def test_aes_roundtrip():
    key = b"\x01" * 32
    iv = b"\x02" * 16
    plaintext = b"Hello, Bitcoin wallet!"
    ciphertext = aes_cbc_encrypt(key, iv, plaintext)
    assert ciphertext != plaintext
    decrypted = aes_cbc_decrypt(key, iv, ciphertext)
    assert decrypted == plaintext


def test_derive_key_iv():
    passphrase = b"test_passphrase"
    salt = b"\x00" * 8
    iterations = 10
    key, iv = derive_key_iv(passphrase, salt, iterations)
    assert len(key) == 32
    assert len(iv) == 16

    # Same inputs should give same outputs
    key2, iv2 = derive_key_iv(passphrase, salt, iterations)
    assert key == key2
    assert iv == iv2


def test_derive_key_iv_different_iterations():
    passphrase = b"test"
    salt = b"\x01" * 8
    key1, iv1 = derive_key_iv(passphrase, salt, 1)
    key2, iv2 = derive_key_iv(passphrase, salt, 2)
    assert key1 != key2
