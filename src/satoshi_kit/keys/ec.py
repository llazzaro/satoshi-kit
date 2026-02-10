"""Elliptic curve key operations wrapping the `ecdsa` library (secp256k1)."""

from __future__ import annotations

import os

import ecdsa  # type: ignore[import-untyped]

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_CURVE = ecdsa.SECP256k1


class ECKey:
    """A secp256k1 private key."""

    def __init__(self, signing_key: ecdsa.SigningKey) -> None:
        self._sk = signing_key

    @classmethod
    def from_secret_exponent(cls, secret: int) -> ECKey:
        """Create from a secret exponent (integer)."""
        secret_bytes = secret.to_bytes(32, "big")
        sk = ecdsa.SigningKey.from_string(secret_bytes, curve=_CURVE)
        return cls(sk)

    @classmethod
    def from_secret_bytes(cls, secret: bytes) -> ECKey:
        """Create from 32 raw secret bytes."""
        sk = ecdsa.SigningKey.from_string(secret, curve=_CURVE)
        return cls(sk)

    @classmethod
    def generate(cls) -> ECKey:
        """Generate a new random key."""
        sk = ecdsa.SigningKey.generate(curve=_CURVE, entropy=os.urandom)
        return cls(sk)

    def secret_bytes(self) -> bytes:
        """Return the 32-byte secret scalar."""
        return bytes(self._sk.to_string())

    def secret_int(self) -> int:
        """Return the secret as an integer."""
        return int.from_bytes(self._sk.to_string(), "big")

    def public_key(self, compressed: bool = True) -> bytes:
        """Return the serialized public key.

        Compressed (33 bytes): 02/03 + x-coordinate
        Uncompressed (65 bytes): 04 + x + y
        """
        vk = self._sk.get_verifying_key()
        if compressed:
            x = vk.pubkey.point.x()
            y = vk.pubkey.point.y()
            prefix = b"\x02" if y % 2 == 0 else b"\x03"
            return prefix + int(x).to_bytes(32, "big")
        else:
            return b"\x04" + bytes(vk.to_string())

    def der_private_key(self, compressed: bool = False) -> bytes:
        """Return the DER-encoded private key (as used by Bitcoin Core).

        This replicates the i2d_ECPrivateKey format from the original satoshi-kit.
        """
        secret_hex = f"{self.secret_int():064x}"
        vk = self._sk.get_verifying_key()
        x_hex = f"{vk.pubkey.point.x():064x}"
        y_hex = f"{vk.pubkey.point.y():064x}"

        curve_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        p_hex = f"{curve_p:064x}"
        gx_hex = f"{gx:064x}"
        gy_hex = f"{gy:064x}"
        r_hex = f"{SECP256K1_ORDER:064x}"

        if compressed:
            part3 = "a08185308182020101302c06072a8648ce3d0101022100"
            pubkey_hex = f"{2 + (vk.pubkey.point.y() & 1):02x}" + x_hex
            key = (
                "3081d30201010420"
                + secret_hex
                + part3
                + p_hex
                + "3006040100040107042102"
                + f"{gx:064x}"
                + "022100"
                + r_hex
                + "020101a124032200"
            )
        else:
            part3 = "a081a53081a2020101302c06072a8648ce3d0101022100"
            pubkey_hex = "04" + x_hex + y_hex
            key = (
                "308201130201010420"
                + secret_hex
                + part3
                + p_hex
                + "3006040100040107044104"
                + gx_hex
                + gy_hex
                + "022100"
                + r_hex
                + "020101a144034200"
            )

        return bytes.fromhex(key) + bytes.fromhex(pubkey_hex)
