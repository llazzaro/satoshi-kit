"""Read and parse wallet.dat files into WalletData."""

from __future__ import annotations

from typing import Any

from satoshi_kit.keys.address import pubkey_to_p2pkh_address
from satoshi_kit.keys.ec import ECKey
from satoshi_kit.keys.wif import secret_to_wif
from satoshi_kit.network import BITCOIN, Network
from satoshi_kit.wallet.encryption import WalletCrypter
from satoshi_kit.wallet.serialization import BCDataStream
from satoshi_kit.wallet.types import MasterKeyInfo, PoolEntry, WalletData, WalletKey


def _privkey_to_secret(privkey: bytes) -> bytes:
    """Extract 32-byte secret from DER-encoded private key."""
    if len(privkey) == 279:
        return privkey[9 : 9 + 32]
    else:
        return privkey[8 : 8 + 32]


def parse_wallet(db: Any, network: Network = BITCOIN) -> WalletData:
    """Parse all entries from an open wallet DB into a WalletData object.

    Args:
        db: An open BerkeleyDB handle (from open_wallet).
        network: Network to use for address generation.

    Returns:
        WalletData with all parsed entries.
    """
    wallet = WalletData()
    kds = BCDataStream()
    vds = BCDataStream()

    for key, value in db.items():
        kds.clear()
        kds.write(key)
        vds.clear()
        vds.write(value)

        entry_type = kds.read_string()

        try:
            if entry_type == b"name":
                addr = kds.read_string().decode("utf-8", errors="replace")
                name = vds.read_string().decode("utf-8", errors="replace")
                wallet.names[addr] = name

            elif entry_type == b"version":
                wallet.version = vds.read_uint32()

            elif entry_type == b"minversion":
                wallet.min_version = vds.read_uint32()

            elif entry_type == b"key":
                pub = kds.read_bytes(kds.read_compact_size())
                priv = vds.read_bytes(vds.read_compact_size())
                secret = _privkey_to_secret(priv)
                compressed = pub[0] != 0x04
                addr = pubkey_to_p2pkh_address(pub, network)
                wif = secret_to_wif(secret, compressed, network)

                wallet.keys.append(
                    WalletKey(
                        addr=addr,
                        pubkey=pub,
                        compressed=compressed,
                        secret=secret,
                        wif=wif,
                        hex_secret=secret.hex(),
                        private_key=priv,
                    )
                )

            elif entry_type == b"ckey":
                pub = kds.read_bytes(kds.read_compact_size())
                enc_priv = vds.read_bytes(vds.read_compact_size())
                compressed = pub[0] != 0x04
                addr = pubkey_to_p2pkh_address(pub, network)
                wallet.crypted = True

                wallet.keys.append(
                    WalletKey(
                        addr=addr,
                        pubkey=pub,
                        compressed=compressed,
                        encrypted_private_key=enc_priv,
                    )
                )

            elif entry_type == b"mkey":
                nid = kds.read_uint32()
                enc_key = vds.read_string()
                salt = vds.read_string()
                method = vds.read_uint32()
                iterations = vds.read_uint32()
                other_params = vds.read_string()

                wallet.master_key = MasterKeyInfo(
                    nid=nid,
                    encrypted_key=enc_key,
                    salt=salt,
                    derivation_method=method,
                    derivation_iterations=iterations,
                    other_params=other_params,
                )

            elif entry_type == b"defaultkey":
                dk = vds.read_bytes(vds.read_compact_size())
                wallet.default_key = pubkey_to_p2pkh_address(dk, network)

            elif entry_type == b"pool":
                n = kds.read_int64()
                n_version = vds.read_int32()
                n_time = vds.read_int64()
                pub = vds.read_bytes(vds.read_compact_size())
                wallet.pool.append(PoolEntry(n=n, n_time=n_time, n_version=n_version, public_key=pub))

        except Exception:
            # Skip entries that can't be parsed
            continue

    return wallet


def read_wallet(
    db_env: Any,
    wallet_file: str,
    passphrase: str | None = None,
    network: Network = BITCOIN,
) -> WalletData:
    """High-level function to read a wallet.dat and optionally decrypt keys.

    Args:
        db_env: BerkeleyDB environment (from create_env).
        wallet_file: Wallet filename within the db_env directory.
        passphrase: Passphrase for encrypted wallets.
        network: Network for address generation.

    Returns:
        WalletData with all keys (decrypted if passphrase provided).
    """
    from satoshi_kit.wallet.bdb import open_wallet

    db = open_wallet(db_env, wallet_file)
    wallet = parse_wallet(db, network)

    # Assign labels
    for key in wallet.keys:
        if key.addr in wallet.names:
            key.label = wallet.names[key.addr]
            key.reserve = False

    # Decrypt if needed
    if wallet.crypted and passphrase and wallet.master_key:
        crypter = WalletCrypter()
        master_key = crypter.decrypt_master_key(wallet.master_key, passphrase)

        verified = False
        for key in wallet.keys:
            if key.encrypted_private_key is not None:
                secret = crypter.decrypt_wallet_key(key, master_key)

                if not verified:
                    # Verify passphrase is correct
                    ec = ECKey.from_secret_bytes(secret)
                    derived_pub = ec.public_key(key.compressed)
                    if derived_pub != key.pubkey:
                        raise ValueError("Incorrect passphrase")
                    verified = True

                key.secret = secret
                key.hex_secret = secret.hex()
                key.wif = secret_to_wif(secret, key.compressed, network)

    db.close()
    return wallet
