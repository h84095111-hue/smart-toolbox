"""Application-level encrypted evidence vault.

Evidence payloads and attachment blobs are encrypted with Fernet. The random
vault key is held by the operating-system credential store (keyring); SQLite
case metadata remains plaintext and this is not full-database encryption.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import uuid

SERVICE = "smart-intel-evidence-vault"
KEY_ACCOUNT = "local-vault-key"


def _fernet(create: bool = False):
    import keyring
    from cryptography.fernet import Fernet
    key = keyring.get_password(SERVICE, KEY_ACCOUNT)
    if not key and create:
        key = Fernet.generate_key().decode("ascii")
        keyring.set_password(SERVICE, KEY_ACCOUNT, key)
    if not key:
        raise RuntimeError("Evidence vault is locked or not enabled on this OS account.")
    return Fernet(key.encode("ascii"))


def vault_enabled() -> bool:
    try:
        return _fernet(False) is not None
    except Exception:
        return False


def enable_vault() -> None:
    _fernet(True)


def encrypt(data: bytes) -> bytes:
    return _fernet(False).encrypt(data)


def decrypt(data: bytes) -> bytes:
    return _fernet(False).decrypt(data)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def import_attachment(root: Path, case_id: str, source_path: str | Path, *, kind: str = "attachment") -> dict:
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(source)
    original = source.read_bytes()
    if len(original) > 100 * 1024 * 1024:
        raise ValueError("Attachments are limited to 100 MiB.")
    encrypted = encrypt(original)
    attachment_id = str(uuid.uuid4())
    destination = Path(root) / "vault" / case_id / (attachment_id + ".fernet")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(encrypted)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "id": attachment_id,
        "case_id": case_id,
        "filename": source.name,
        "kind": kind,
        "path": str(destination),
        "size": len(original),
        "sha256": sha256(original),
        "ciphertext_sha256": sha256(encrypted),
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }


def read_attachment(row: dict) -> bytes:
    encrypted = Path(row["path"]).read_bytes()
    if sha256(encrypted) != row["ciphertext_sha256"]:
        raise ValueError("Encrypted attachment hash mismatch.")
    original = decrypt(encrypted)
    if sha256(original) != row["sha256"]:
        raise ValueError("Decrypted attachment hash mismatch.")
    return original



def make_warc_response(url: str) -> bytes:
    """Capture one safely fetched public HTTP response as a WARC response record."""
    from datetime import datetime, timezone
    import uuid as uuid_module
    from urllib.parse import urlparse
    from .collectors.passive import _get_public_pinned

    parsed = urlparse(url if "://" in url else "https://" + url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")
    if parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
        raise ValueError("WARC capture accepts only standard public HTTP(S) URLs without embedded credentials.")
    response = _get_public_pinned(parsed.geturl())
    reason = str(response.reason or "OK")
    status_line = f"HTTP/1.1 {response.status_code} {reason}\r\n"
    headers = "".join(f"{key}: {value}\r\n" for key, value in response.headers.items())
    http_message = (status_line + headers + "\r\n").encode("iso-8859-1", errors="replace") + response.content
    warc_headers = (
        "WARC/1.1\r\n"
        "WARC-Type: response\r\n"
        f"WARC-Record-ID: <urn:uuid:{uuid_module.uuid4()}>\r\n"
        f"WARC-Date: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\r\n"
        f"WARC-Target-URI: {parsed.geturl()}\r\n"
        "Content-Type: application/http; msgtype=response\r\n"
        f"Content-Length: {len(http_message)}\r\n\r\n"
    ).encode("utf-8")
    return warc_headers + http_message + b"\r\n\r\n"

def make_warc_record(source_path: str | Path, target_uri: str | None = None) -> bytes:
    """Create a WARC/1.1 resource record for an imported local artifact."""
    from datetime import datetime, timezone
    import mimetypes
    import uuid as uuid_module
    source = Path(source_path)
    payload = source.read_bytes()
    if len(payload) > 100 * 1024 * 1024:
        raise ValueError("WARC source is limited to 100 MiB.")
    uri = target_uri or source.resolve().as_uri()
    content_type = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
    headers = (
        "WARC/1.1\r\n"
        f"WARC-Type: resource\r\n"
        f"WARC-Record-ID: <urn:uuid:{uuid_module.uuid4()}>\r\n"
        f"WARC-Date: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\r\n"
        f"WARC-Target-URI: {uri}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(payload)}\r\n\r\n"
    ).encode("utf-8")
    return headers + payload + b"\r\n\r\n"
