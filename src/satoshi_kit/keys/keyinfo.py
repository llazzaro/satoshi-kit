"""High-level key info extraction — the keyinfo() function and KeyInfo dataclass."""

from __future__ import annotations

from dataclasses import dataclass

from satoshi_kit.keys.address import (
    pubkey_to_ethereum_address,
    pubkey_to_p2pkh_address,
)
from satoshi_kit.keys.ec import ECKey
from satoshi_kit.keys.wif import secret_to_wif, wif_to_secret
from satoshi_kit.network import BITCOIN, ETHEREUM, Network


@dataclass(frozen=True)
class KeyInfo:
    """Information derived from a private key."""

    secret: bytes
    private_key: bytes
    public_key: bytes
    uncompressed_public_key: bytes
    addr: str
    wif: str | None
    compressed: bool


def _parse_private_key(sec: str, force_compressed: bool | None = None) -> tuple[ECKey, bool]:
    """Parse a private key from WIF or hex string."""
    # Try WIF first
    try:
        secret_bytes, wif_compressed = wif_to_secret(sec)
        compressed = wif_compressed if force_compressed is None else force_compressed
        return ECKey.from_secret_bytes(secret_bytes), compressed
    except (ValueError, Exception):
        pass

    # Try hex
    try:
        hex_str = sec
        if len(hex_str) == 64:
            compressed = False if force_compressed is None else force_compressed
            return ECKey.from_secret_bytes(bytes.fromhex(hex_str)), compressed
        elif len(hex_str) == 66 and hex_str.endswith("01"):
            compressed = True if force_compressed is None else force_compressed
            return ECKey.from_secret_bytes(bytes.fromhex(hex_str[:64])), compressed
        elif len(hex_str) < 64:
            compressed = False if force_compressed is None else force_compressed
            padded = hex_str.zfill(64)
            return ECKey.from_secret_bytes(bytes.fromhex(padded)), compressed
        else:
            raise ValueError(f"Cannot parse private key: {sec!r}")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Cannot parse private key: {sec!r}") from exc


def keyinfo(
    sec: str,
    network: Network | None = None,
    force_compressed: bool | None = None,
) -> KeyInfo:
    """Derive full key information from a WIF or hex private key string.

    Args:
        sec: Private key as WIF string or hex string.
        network: Network to use (defaults to BITCOIN).
        force_compressed: Override compressed/uncompressed. None = auto-detect.

    Returns:
        A KeyInfo dataclass with all derived information.
    """
    network = network or BITCOIN

    pkey, compressed = _parse_private_key(sec, force_compressed)

    secret = pkey.secret_bytes()
    private_key = pkey.der_private_key(compressed)
    public_key = pkey.public_key(compressed)
    uncompressed_public_key = pkey.public_key(False)

    # Determine address based on network
    if network == ETHEREUM:
        addr = pubkey_to_ethereum_address(uncompressed_public_key)
    else:
        addr = pubkey_to_p2pkh_address(public_key, network)

    wif = secret_to_wif(secret, compressed, network)

    return KeyInfo(
        secret=secret,
        private_key=private_key,
        public_key=public_key,
        uncompressed_public_key=uncompressed_public_key,
        addr=addr,
        wif=wif,
        compressed=compressed,
    )
