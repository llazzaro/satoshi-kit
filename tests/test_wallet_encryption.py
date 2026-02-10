"""Tests for wallet/encryption.py."""

from satoshi_kit.crypto.aes import aes_cbc_encrypt, derive_key_iv
from satoshi_kit.wallet.encryption import WalletCrypter
from satoshi_kit.wallet.types import MasterKeyInfo


def test_crypter_encrypt_decrypt_roundtrip():
    crypter = WalletCrypter()
    passphrase = b"testpassword"
    salt = b"\x00" * 8
    iterations = 10

    crypter.set_key_from_passphrase(passphrase, salt, iterations, method=0)

    plaintext = b"\x01" * 32
    encrypted = crypter.encrypt(plaintext)
    assert encrypted != plaintext

    decrypted = crypter.decrypt(encrypted)
    assert decrypted == plaintext


def test_derive_key_iv_consistency():
    """Ensure custom SHA-512 derivation is deterministic."""
    key1, iv1 = derive_key_iv(b"pass", b"\x01" * 8, 100)
    key2, iv2 = derive_key_iv(b"pass", b"\x01" * 8, 100)
    assert key1 == key2
    assert iv1 == iv2


def test_decrypt_master_key():
    """Test decrypt_master_key with a synthetic master key."""
    passphrase = "testpassword"
    salt = b"\xab" * 8
    iterations = 5

    # Encrypt a known master key
    key, iv = derive_key_iv(passphrase.encode(), salt, iterations)
    real_master_key = b"\xfe" * 32
    encrypted_mk = aes_cbc_encrypt(key, iv, real_master_key)

    mki = MasterKeyInfo(
        nid=1,
        encrypted_key=encrypted_mk,
        salt=salt,
        derivation_method=0,
        derivation_iterations=iterations,
    )

    crypter = WalletCrypter()
    decrypted = crypter.decrypt_master_key(mki, passphrase)
    assert decrypted == real_master_key
