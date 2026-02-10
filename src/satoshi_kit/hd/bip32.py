"""BIP-32 hierarchical deterministic key derivation."""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

from satoshi_kit.crypto.base58 import decode_base58check, encode_base58check
from satoshi_kit.crypto.hashing import hash_160
from satoshi_kit.hd.bip39 import Mnemonic
from satoshi_kit.keys.ec import SECP256K1_ORDER, ECKey

_XPRIV_VERSION = 0x0488ADE4
_XPUB_VERSION = 0x0488B21E
_STRUCT_FMT = ">IB4sI32sB32s"
_HARDENED = 0x80000000


@dataclass(frozen=True)
class Xpriv:
    """BIP-32 extended private key."""

    version: int
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    key_type: int  # 0 for private, 2/3 for compressed public
    key: bytes
    full_path: str = field(default="m", compare=False, repr=False)

    @classmethod
    def from_seed(cls, seed: bytes, hmac_key: bytes = b"Bitcoin seed") -> Xpriv:
        """Create a master key from a seed (BIP-32 master key generation)."""
        i = hmac.new(hmac_key, seed, digestmod=hashlib.sha512).digest()
        master_key, chain_code = i[:32], i[32:]
        return cls(
            version=_XPRIV_VERSION,
            depth=0,
            parent_fingerprint=b"\x00" * 4,
            child_number=0,
            chain_code=chain_code,
            key_type=0,
            key=master_key,
        )

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "") -> Xpriv:
        """Create a master key from a BIP-39 mnemonic."""
        seed = Mnemonic.to_seed(mnemonic, passphrase)
        return cls.from_seed(seed)

    @classmethod
    def from_base58(cls, b58: str) -> Xpriv:
        """Deserialize from a Base58Check-encoded string (xprv...)."""
        decoded = decode_base58check(b58)
        if decoded is None:
            raise ValueError("Invalid xpriv: checksum failed")
        fields = struct.unpack(_STRUCT_FMT, decoded)
        return cls(*fields)

    def to_base58(self) -> str:
        """Serialize to Base58Check (xprv...)."""
        packed = struct.pack(
            _STRUCT_FMT,
            self.version,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            self.chain_code,
            self.key_type,
            self.key,
        )
        return encode_base58check(packed)

    def to_xpub(self, network_name: str | None = None) -> str:
        """Derive the extended public key (xpub...) as Base58Check string."""
        assert self.key_type == 0, "Can only derive xpub from xpriv"
        ec = ECKey.from_secret_bytes(self.key)
        pubkey = ec.public_key(compressed=True)
        packed = struct.pack(
            _STRUCT_FMT,
            _XPUB_VERSION,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            self.chain_code,
            pubkey[0],  # 0x02 or 0x03
            pubkey[1:],  # 32-byte x coordinate
        )
        return encode_base58check(packed)

    def derive_child(self, index: int) -> Xpriv:
        """Derive a single child key (BIP-32 CKD)."""
        assert self.key_type == 0, "Can only derive children from private key"

        ec = ECKey.from_secret_bytes(self.key)
        parent_pubkey = ec.public_key(compressed=True)
        ser_index = struct.pack(">I", index)

        if index >= _HARDENED:
            # Hardened child
            data = b"\x00" + self.key + ser_index
        else:
            # Normal child
            data = parent_pubkey + ser_index

        i = hmac.new(self.chain_code, data, digestmod=hashlib.sha512).digest()
        il, ir = i[:32], i[32:]

        # (il + parent_key) % curve_order
        il_int = int.from_bytes(il, "big")
        key_int = int.from_bytes(self.key, "big")
        child_key_int = (il_int + key_int) % SECP256K1_ORDER
        child_key = child_key_int.to_bytes(32, "big")

        fingerprint = hash_160(parent_pubkey)[:4]

        # Build path string
        if index >= _HARDENED:
            path_segment = f"{index - _HARDENED}'"
        else:
            path_segment = str(index)
        new_path = self.full_path + "/" + path_segment

        return Xpriv(
            version=self.version,
            depth=self.depth + 1,
            parent_fingerprint=fingerprint,
            child_number=index,
            chain_code=ir,
            key_type=0,
            key=child_key,
            full_path=new_path,
        )

    def derive_path(self, path: str) -> Xpriv:
        """Derive a key at a BIP-32 path like "m/44'/0'/0'/0/0".

        Each path component supports:
        - N: normal child derivation
        - N' or Nh: hardened child derivation
        """
        components = _parse_path(path)
        current = self
        for index in components:
            current = current.derive_child(index)
        return current

    def derive_path_multi(self, path: str) -> list[Xpriv]:
        """Derive keys at a path with range notation.

        Supports ranges like "m/7-8'/3/99'/38-39" which expand to all combinations.
        """
        path_split = _parse_path_multi(path)
        rev = path_split[::-1]
        results: list[Xpriv] = [self]
        while rev:
            children_nrs = rev.pop()
            results = [parent.derive_child(child_nr) for parent in results for child_nr in children_nrs]
        return results


def _parse_path(path: str) -> list[int]:
    """Parse a simple BIP-32 path into a list of child indices."""
    path = path.lstrip("m").lstrip("/")
    if not path:
        return []
    result: list[int] = []
    for component in path.split("/"):
        if not component:
            continue
        hardened = 0
        if component.endswith("'") or component.lower().endswith("h"):
            hardened = _HARDENED
            component = component[:-1]
        result.append(int(component) + hardened)
    return result


def _parse_path_multi(path: str) -> list[list[int]]:
    """Parse a BIP-32 path with range notation into lists of child indices."""
    path = path.lstrip("m").lstrip("/")
    result: list[list[int]] = []
    for component in path.split("/"):
        if not component:
            continue
        hardened = 0
        if component.endswith("'") or component.lower().endswith("h"):
            hardened = _HARDENED
            component = component[:-1]
        if "-" in component:
            a_str, b_str = component.split("-", 1)
            a, b = int(a_str), int(b_str)
            result.append(list(range(a + hardened, b + 1 + hardened)))
        else:
            result.append([int(component) + hardened])
    return result
