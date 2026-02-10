"""BerkeleyDB wrapper for wallet.dat operations.

Requires optional dependency: ``pip install satoshi-kit[wallet]``
"""

from __future__ import annotations

import struct
from typing import Any

try:
    from bsddb3.db import (  # type: ignore[import-not-found]
        DB,
        DB_BTREE,
        DB_CREATE,
        DB_INIT_LOCK,
        DB_INIT_LOG,
        DB_INIT_MPOOL,
        DB_INIT_TXN,
        DB_RDONLY,
        DB_RECOVER,
        DB_THREAD,
        DBEnv,
        DBError,
    )

    _HAS_BSDDB3 = True
except ImportError:
    _HAS_BSDDB3 = False


def _check_bsddb3() -> None:
    if not _HAS_BSDDB3:
        raise ImportError(
            "bsddb3 is required for wallet.dat operations. "
            "Install it with: pip install satoshi-kit[wallet]"
        )


def create_env(db_dir: str) -> Any:
    """Create a BerkeleyDB environment for the given directory."""
    _check_bsddb3()
    db_env = DBEnv(0)
    db_env.open(
        db_dir,
        DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN | DB_THREAD | DB_RECOVER,
    )
    return db_env


def open_wallet(db_env: Any, wallet_file: str, writable: bool = False) -> Any:
    """Open a wallet.dat file within a BerkeleyDB environment."""
    _check_bsddb3()
    db = DB(db_env)
    flags = DB_THREAD | (DB_CREATE if writable else DB_RDONLY)
    try:
        r = db.open(wallet_file, "main", DB_BTREE, flags)
    except DBError as e:
        raise OSError(f"Failed to open {wallet_file}: {e}") from e

    if r is not None:
        raise OSError(f"Failed to open {wallet_file}/main")

    return db


def create_new_wallet(db_env: Any, wallet_file: str, version: int) -> None:
    """Create a new empty wallet.dat with the given version."""
    _check_bsddb3()
    db_out = DB(db_env)
    try:
        r = db_out.open(wallet_file, "main", DB_BTREE, DB_CREATE)
    except DBError as e:
        raise OSError(f"Failed to create {wallet_file}: {e}") from e

    if r is not None:
        raise OSError(f"Failed to create {wallet_file}/main")

    # Write version record
    version_key = bytes.fromhex("0776657273696f6e")  # \x07version
    version_val = struct.pack("<I", version)
    db_out.put(version_key, version_val)
    db_out.close()
