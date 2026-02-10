"""Data types for wallet operations."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MasterKeyInfo:
    """Master key encryption metadata from wallet.dat."""

    nid: int
    encrypted_key: bytes
    salt: bytes
    derivation_method: int
    derivation_iterations: int
    other_params: bytes = b""


@dataclass
class WalletKey:
    """A key entry from wallet.dat."""

    addr: str
    pubkey: bytes
    compressed: bool
    # Unencrypted keys have these:
    secret: bytes | None = None
    wif: str | None = None
    hex_secret: str | None = None
    private_key: bytes | None = None
    # Encrypted keys have this:
    encrypted_private_key: bytes | None = None
    label: str | None = None
    reserve: bool = True


@dataclass
class PoolEntry:
    """A key pool entry from wallet.dat."""

    n: int
    n_time: int
    n_version: int
    public_key: bytes


@dataclass
class WalletData:
    """All data parsed from a wallet.dat file."""

    version: int | None = None
    min_version: int | None = None
    keys: list[WalletKey] = field(default_factory=list)
    pool: list[PoolEntry] = field(default_factory=list)
    names: dict[str, str] = field(default_factory=dict)
    master_key: MasterKeyInfo | None = None
    default_key: str | None = None
    crypted: bool = False
