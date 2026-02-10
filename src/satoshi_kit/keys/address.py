"""Bitcoin and Ethereum address generation from public keys."""

from __future__ import annotations

from satoshi_kit.crypto.base58 import encode_base58check
from satoshi_kit.crypto.bech32 import bech32_encode
from satoshi_kit.crypto.hashing import hash_160, keccak256
from satoshi_kit.network import BITCOIN, Network


def _hash160_to_address(h160: bytes, version: int) -> str:
    """Encode a 20-byte hash160 with a version prefix to a base58check address."""
    return encode_base58check(bytes([version]) + h160)


def pubkey_to_p2pkh_address(pubkey: bytes, network: Network = BITCOIN) -> str:
    """P2PKH address from a serialized public key (compressed or uncompressed)."""
    return _hash160_to_address(hash_160(pubkey), network.p2pkh_prefix)


def pubkey_to_p2sh_p2wpkh_address(pubkey: bytes, network: Network = BITCOIN) -> str:
    """P2SH-P2WPKH address (nested SegWit) from a compressed public key."""
    keyhash = hash_160(pubkey)
    redeem_script = b"\x00\x14" + keyhash  # OP_0 <20-byte-hash>
    return _hash160_to_address(hash_160(redeem_script), network.p2sh_prefix)


def pubkey_to_bech32_address(pubkey: bytes, network: Network = BITCOIN) -> str:
    """P2WPKH native SegWit (bech32) address from a compressed public key."""
    if network.segwit_hrp is None:
        raise ValueError(f"Network {network.name} does not support SegWit")
    keyhash = hash_160(pubkey)
    return bech32_encode(network.segwit_hrp, 0, keyhash)


def eip55_checksum(hex_addr: str) -> str:
    """Apply EIP-55 mixed-case checksum to a hex Ethereum address.

    Input should be 40 hex characters (with or without '0x' prefix).
    Returns address with '0x' prefix and mixed-case checksum.
    """
    if hex_addr.startswith("0x") or hex_addr.startswith("0X"):
        hex_addr = hex_addr[2:]
    hex_addr = hex_addr.lower()

    addr_hash = keccak256(hex_addr.encode("ascii")).hex()

    checksummed = ""
    for i, char in enumerate(hex_addr):
        if char in "0123456789":
            checksummed += char
        elif char in "abcdef":
            if int(addr_hash[i], 16) > 7:
                checksummed += char.upper()
            else:
                checksummed += char
        else:
            raise ValueError(f"Unrecognized hex character {char!r} at position {i}")

    return "0x" + checksummed


def pubkey_to_ethereum_address(uncompressed_pubkey: bytes) -> str:
    """Derive an EIP-55 checksummed Ethereum address from an uncompressed public key.

    The input should be the 65-byte uncompressed key (04 + x + y) or
    the 64-byte raw point (x + y, no prefix).
    """
    if len(uncompressed_pubkey) == 65:
        # Strip the 0x04 prefix
        raw = uncompressed_pubkey[1:]
    elif len(uncompressed_pubkey) == 64:
        raw = uncompressed_pubkey
    else:
        raise ValueError(f"Expected 64 or 65 byte uncompressed pubkey, got {len(uncompressed_pubkey)}")

    addr_bytes = keccak256(raw)[-20:]
    return eip55_checksum(addr_bytes.hex())
