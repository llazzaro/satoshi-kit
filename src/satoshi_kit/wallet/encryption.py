"""Wallet encryption/decryption — unified WalletCrypter replacing 3 Crypter classes."""

from __future__ import annotations

from satoshi_kit.crypto.aes import aes_cbc_decrypt_raw, aes_cbc_encrypt, derive_key_iv
from satoshi_kit.crypto.hashing import double_sha256
from satoshi_kit.wallet.types import MasterKeyInfo, WalletKey


class WalletCrypter:
    """Handles wallet encryption/decryption using AES-256-CBC.

    Uses the custom iterated SHA-512 key derivation that Bitcoin Core uses
    (NOT PBKDF2, NOT EVP_BytesToKey).
    """

    def __init__(self) -> None:
        self._key: bytes | None = None
        self._iv: bytes | None = None

    def set_key_from_passphrase(
        self,
        passphrase: bytes,
        salt: bytes,
        iterations: int,
        method: int,
    ) -> None:
        """Derive AES key and IV from passphrase + salt."""
        if method != 0:
            raise ValueError(f"Unsupported derivation method: {method}")
        self._key, self._iv = derive_key_iv(passphrase, salt, iterations)

    def set_key(self, key: bytes) -> None:
        self._key = key

    def set_iv(self, iv: bytes) -> None:
        self._iv = iv[:16]

    def encrypt(self, plaintext: bytes) -> bytes:
        assert self._key is not None and self._iv is not None
        return aes_cbc_encrypt(self._key, self._iv, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt and return raw 32-byte result (no padding strip)."""
        assert self._key is not None and self._iv is not None
        return aes_cbc_decrypt_raw(self._key, self._iv, ciphertext)

    def decrypt_master_key(self, master_key_info: MasterKeyInfo, passphrase: str) -> bytes:
        """Decrypt the master key using a passphrase."""
        self.set_key_from_passphrase(
            passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase,
            master_key_info.salt,
            master_key_info.derivation_iterations,
            master_key_info.derivation_method,
        )
        return self.decrypt(master_key_info.encrypted_key)

    def decrypt_wallet_key(self, wallet_key: WalletKey, master_key: bytes) -> bytes:
        """Decrypt a single wallet key using the decrypted master key."""
        if wallet_key.encrypted_private_key is None:
            raise ValueError("Key is not encrypted")
        self.set_key(master_key)
        self.set_iv(double_sha256(wallet_key.pubkey))
        return self.decrypt(wallet_key.encrypted_private_key)
