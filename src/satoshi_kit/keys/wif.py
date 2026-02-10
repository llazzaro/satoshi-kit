"""WIF (Wallet Import Format) encoding and decoding."""

from __future__ import annotations

from satoshi_kit.crypto.base58 import decode_base58check, encode_base58check
from satoshi_kit.network import BITCOIN, Network


def secret_to_wif(secret: bytes, compressed: bool = False, network: Network = BITCOIN) -> str:
    """Encode a 32-byte secret as WIF."""
    prefix = bytes([network.wif_prefix])
    payload = prefix + secret
    if compressed:
        payload += b"\x01"
    return encode_base58check(payload)


def wif_to_secret(wif: str, network: Network | None = None) -> tuple[bytes, bool]:
    """Decode a WIF string to (secret_bytes, compressed).

    If network is provided, validates the prefix. Raises ValueError on failure.
    """
    decoded = decode_base58check(wif)
    if decoded is None:
        raise ValueError("Invalid WIF: checksum failed")

    if network is not None and decoded[0] != network.wif_prefix:
        raise ValueError(
            f"WIF prefix mismatch: expected {network.wif_prefix:#x}, got {decoded[0]:#x}"
        )

    if len(decoded) == 34 and decoded[-1] == 0x01:
        return decoded[1:33], True
    elif len(decoded) == 33:
        return decoded[1:33], False
    else:
        raise ValueError(f"Unexpected WIF payload length: {len(decoded)}")
