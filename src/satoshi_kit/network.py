"""Network definitions for Bitcoin, Testnet, and Ethereum."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Network:
    """Immutable network configuration."""

    name: str
    p2pkh_prefix: int
    p2sh_prefix: int
    wif_prefix: int
    segwit_hrp: str | None


BITCOIN = Network(
    name="Bitcoin",
    p2pkh_prefix=0x00,
    p2sh_prefix=0x05,
    wif_prefix=0x80,
    segwit_hrp="bc",
)

BITCOIN_TESTNET3 = Network(
    name="Bitcoin-Testnet3",
    p2pkh_prefix=0x6F,
    p2sh_prefix=0xC4,
    wif_prefix=0xEF,
    segwit_hrp="tb",
)

ETHEREUM = Network(
    name="Ethereum",
    p2pkh_prefix=0x00,
    p2sh_prefix=0x05,
    wif_prefix=0x80,
    segwit_hrp=None,
)

_ALL_NETWORKS = [BITCOIN, BITCOIN_TESTNET3, ETHEREUM]


def find_network(name: str) -> Network | None:
    """Find a network by case-insensitive name."""
    for n in _ALL_NETWORKS:
        if n.name.lower() == name.lower():
            return n
    return None
