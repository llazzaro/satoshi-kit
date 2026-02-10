"""Write operations for wallet.dat files."""

from __future__ import annotations

from typing import Any

from satoshi_kit.crypto.hashing import double_sha256
from satoshi_kit.keys.address import pubkey_to_p2pkh_address
from satoshi_kit.keys.keyinfo import keyinfo
from satoshi_kit.network import BITCOIN, Network
from satoshi_kit.wallet.encryption import WalletCrypter
from satoshi_kit.wallet.serialization import BCDataStream
from satoshi_kit.wallet.types import MasterKeyInfo


def update_wallet(db: Any, entry_type: str, data: dict[str, Any]) -> None:
    """Write a single item to an open wallet DB.

    Args:
        db: An open writable BerkeleyDB handle.
        entry_type: The record type (e.g. "key", "ckey", "name", "mkey", etc.).
        data: Dictionary of fields for the record.
    """
    type_bytes = entry_type.encode("utf-8") if isinstance(entry_type, str) else entry_type
    kds = BCDataStream()
    vds = BCDataStream()

    kds.write_string(type_bytes)

    if type_bytes == b"name":
        kds.write_string(data["hash"].encode("utf-8") if isinstance(data["hash"], str) else data["hash"])
        vds.write_string(data["name"].encode("utf-8") if isinstance(data["name"], str) else data["name"])
    elif type_bytes == b"version":
        vds.write_uint32(data["version"])
    elif type_bytes == b"minversion":
        vds.write_uint32(data["minversion"])
    elif type_bytes == b"key":
        kds.write_string(data["public_key"])
        vds.write_string(data["private_key"])
    elif type_bytes == b"ckey":
        kds.write_string(data["public_key"])
        vds.write_string(data["encrypted_private_key"])
    elif type_bytes == b"defaultkey":
        vds.write_string(data["key"])
    elif type_bytes == b"pool":
        kds.write_int64(data["n"])
        vds.write_int32(data["nVersion"])
        vds.write_int64(data["nTime"])
        vds.write_string(data["public_key"])
    elif type_bytes == b"mkey":
        kds.write_uint32(data["nID"])
        vds.write_string(data["encrypted_key"])
        vds.write_string(data["salt"])
        vds.write_uint32(data["nDerivationMethod"])
        vds.write_uint32(data["nDerivationIterations"])
        vds.write_string(data["otherParams"])
    else:
        raise ValueError(f"Unknown entry type: {entry_type}")

    db.put(kds.input, vds.input)


def import_private_key(
    db: Any,
    secret: str,
    label: str = "",
    reserve: bool = False,
    network: Network = BITCOIN,
    master_key_info: MasterKeyInfo | None = None,
    passphrase: str | None = None,
) -> str:
    """Import a private key into an open writable wallet DB.

    Args:
        db: An open writable BerkeleyDB handle.
        secret: Private key as WIF or hex string.
        label: Address book label.
        reserve: If True, import as reserve key (no address book entry).
        network: Network to use.
        master_key_info: If wallet is encrypted, provide master key info.
        passphrase: If wallet is encrypted, provide passphrase.

    Returns:
        The address of the imported key.
    """
    ki = keyinfo(secret, network=network, force_compressed=None)

    if master_key_info and passphrase:
        # Encrypted wallet: encrypt the secret before storing
        crypter = WalletCrypter()
        master_key = crypter.decrypt_master_key(master_key_info, passphrase)
        crypter.set_key(master_key)
        crypter.set_iv(double_sha256(ki.public_key))
        encrypted_pk = crypter.encrypt(ki.secret)
        update_wallet(db, "ckey", {"public_key": ki.public_key, "encrypted_private_key": encrypted_pk})
    else:
        update_wallet(db, "key", {"public_key": ki.public_key, "private_key": ki.private_key})

    if not reserve:
        update_wallet(db, "name", {"hash": ki.addr, "name": label})

    return ki.addr


def delete_from_wallet(db: Any, entry_type: str, keys_to_delete: list[str], network: Network = BITCOIN) -> int:
    """Delete entries from a wallet DB.

    Args:
        db: An open writable BerkeleyDB handle.
        entry_type: Type of entry to delete ("key" or "tx").
        keys_to_delete: List of addresses or tx ids to delete.
        network: Network for address resolution.

    Returns:
        Number of deleted items.
    """
    deleted = 0
    kds = BCDataStream()
    vds = BCDataStream()

    if entry_type == "tx" and keys_to_delete != ["all"]:
        for txid in keys_to_delete:
            db.delete(b"\x02\x74\x78" + bytes.fromhex(txid)[::-1])
            deleted += 1
    else:
        for key, value in list(db.items()):
            kds.clear()
            kds.write(key)
            vds.clear()
            vds.write(value)
            rec_type = kds.read_string()

            if entry_type == "tx" and rec_type == b"tx":
                db.delete(key)
                deleted += 1
            elif entry_type == "key":
                for keydel in keys_to_delete:
                    if rec_type in (b"key", b"ckey"):
                        pub = kds.read_bytes(kds.read_compact_size())
                        if keydel == pubkey_to_p2pkh_address(pub, network):
                            db.delete(key)
                            deleted += 1
                    elif rec_type == b"name":
                        addr = kds.read_string().decode("utf-8", errors="replace")
                        if keydel == addr:
                            db.delete(key)
                            deleted += 1

    return deleted
