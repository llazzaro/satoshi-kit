"""Bech32 encoding for SegWit addresses (BIP173)."""

from __future__ import annotations

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= _GENERATOR[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding")
    return ret


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a witness program into a Bech32 address.

    Args:
        hrp: Human-readable part (e.g. 'bc' for mainnet, 'tb' for testnet).
        witver: Witness version (0 for P2WPKH/P2WSH).
        witprog: Witness program bytes (e.g. 20-byte hash for P2WPKH).
    """
    data = [witver] + _convertbits(witprog, 8, 5)
    combined = data + _create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in combined)
