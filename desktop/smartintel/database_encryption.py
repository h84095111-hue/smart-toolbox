"""Optional SQLCipher database-page encryption.

Requires sqlcipher3-binary. Existing databases are converted into a temporary
encrypted copy; the plaintext original is retained as a clearly named backup.
The key is stored in the OS credential store. Never silently fall back to
plaintext when a key has already been configured.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import secrets
import hashlib

SERVICE = "smart-intel"
ACCOUNT = "sqlcipher_database_key"


def _account_for(path: str | Path) -> str:
    identity = str(Path(path).expanduser().resolve()).encode("utf-8")
    return ACCOUNT + ":" + hashlib.sha256(identity).hexdigest()[:32]


def get_database_key(path: str | Path | None = None) -> str | None:
    try:
        import keyring
        if path is None:
            from .config import DB_PATH
            path = DB_PATH
        return keyring.get_password(SERVICE, _account_for(path))
    except Exception:
        return None


def database_encryption_enabled(path: str | Path | None = None) -> bool:
    if path is None:
        from .config import DB_PATH
        path = DB_PATH
    marker = Path(str(path) + ".sqlcipher-required")
    return bool(get_database_key(path)) or marker.exists()


def _sqlcipher():
    try:
        from sqlcipher3 import dbapi2 as driver
        return driver
    except ImportError as exc:
        raise RuntimeError("Full SQLite encryption requires sqlcipher3-binary. Install desktop/requirements-optional.txt and restart.") from exc


def encrypted_connect(path: str | Path):
    key = get_database_key(path)
    if not key:
        raise RuntimeError("SQLCipher key is not available in the OS credential store.")
    driver = _sqlcipher()
    connection = driver.connect(str(path), timeout=30)
    connection.execute(f"PRAGMA key = {_quote_sql(key)}")
    connection.row_factory = driver.Row
    try:
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        connection.execute("PRAGMA cipher_memory_security = ON")
    except Exception:
        connection.close()
        raise RuntimeError("Cannot decrypt the case database. Check the OS keyring and preserve the database file.")
    return connection


def _quote_sql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def encrypt_database(path: str | Path) -> dict:
    """Convert a plaintext SQLite DB to SQLCipher without overwriting on failure."""
    database = Path(path)
    if not database.is_file():
        raise FileNotFoundError(database)
    if database_encryption_enabled(database):
        raise RuntimeError("This database already has a SQLCipher key configured.")
    driver = _sqlcipher()
    import sqlite3
    with sqlite3.connect(str(database), timeout=30) as plain:
        plain.execute("PRAGMA wal_checkpoint(FULL)")
        plain.execute("PRAGMA journal_mode=DELETE")
        plain.commit()

    backup = database.with_suffix(database.suffix + ".plaintext-backup")
    temporary = database.with_suffix(database.suffix + ".sqlcipher.tmp")
    if backup.exists():
        raise FileExistsError(f"Refusing to overwrite existing plaintext backup: {backup}")
    temporary.unlink(missing_ok=True)
    key = secrets.token_urlsafe(48)
    source = driver.connect(str(database), timeout=30)
    try:
        # SQLCipher must explicitly open the legacy plaintext SQLite source
        # before sqlcipher_export can copy it into the keyed destination.
        source.execute("PRAGMA key = ''")
        source.execute("SELECT count(*) FROM sqlite_master").fetchone()
        source.execute(f"ATTACH DATABASE {_quote_sql(str(temporary))} AS encrypted KEY {_quote_sql(key)}")
        source.execute("SELECT sqlcipher_export('encrypted')")
        source.execute("DETACH DATABASE encrypted")
    except Exception:
        source.close()
        temporary.unlink(missing_ok=True)
        raise
    source.close()

    verify = driver.connect(str(temporary), timeout=30)
    try:
        verify.execute(f"PRAGMA key = {_quote_sql(key)}")
        verify.execute("SELECT count(*) FROM sqlite_master").fetchone()
        integrity = verify.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise RuntimeError("SQLCipher integrity check failed; original database was not changed.")
    finally:
        verify.close()

    import keyring
    marker = Path(str(database) + ".sqlcipher-required")
    marker_tmp = marker.with_suffix(marker.suffix + ".tmp")
    marker_tmp.write_text("SQLCipher is required to open this database. Do not remove this marker.\\n", encoding="utf-8")
    try:
        os.chmod(marker_tmp, 0o600)
        keyring.set_password(SERVICE, _account_for(database), key)
        marker_tmp.replace(marker)
        shutil.copy2(database, backup)
        os.replace(temporary, database)
    except Exception:
        marker_tmp.unlink(missing_ok=True)
        try:
            if marker.exists():
                marker.unlink()
            keyring.delete_password(SERVICE, _account_for(database))
        except Exception:
            pass
        temporary.unlink(missing_ok=True)
        raise
    for suffix in ("-wal", "-shm"):
        Path(str(database) + suffix).unlink(missing_ok=True)
    return {"encrypted": True, "database": str(database), "plaintext_backup": str(backup),
            "algorithm": "SQLCipher (AES-256 page encryption)",
            "key_storage": "OS credential store"}
