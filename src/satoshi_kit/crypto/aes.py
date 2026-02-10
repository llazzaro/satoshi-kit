"""AES-256-CBC encryption/decryption and wallet key derivation.

Replaces the hand-rolled SlowAES and 3 Crypter classes from the original
satoshi-kit with the `cryptography` library.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def derive_key_iv(passphrase: bytes, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """Derive AES-256 key and IV from passphrase using iterated SHA-512.

    This is the **custom** key derivation used by Bitcoin Core wallet encryption.
    It is NOT PBKDF2 and NOT EVP_BytesToKey — it is simply:
        data = passphrase + salt
        for i in range(iterations):
            data = SHA-512(data)
        key = data[0:32]
        iv  = data[32:48]

    This must be replicated exactly for encrypted wallet.dat compatibility.
    """
    data = passphrase + salt
    for _ in range(iterations):
        data = hashlib.sha512(data).digest()
    return data[:32], data[32:48]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC encrypt with PKCS7 padding."""
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC decrypt and strip PKCS7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_cbc_decrypt_raw(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC decrypt without stripping padding.

    Used for wallet key decryption where Bitcoin Core expects
    exactly 32 bytes of output (the raw decrypted block).
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize())[:32]
