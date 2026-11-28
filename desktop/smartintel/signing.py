"""Ed25519 signed evidence bundles with optional RFC 3161 timestamping."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone

from .providers.ai import get_api_key, save_api_key


def _signing_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import base64
    encoded = get_api_key("export_signing_private_key")
    if encoded:
        raw = base64.b64decode(encoded)
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    save_api_key("export_signing_private_key", base64.b64encode(raw).decode("ascii"))
    return key


def signed_export(case: dict, evidence: list[dict], output_path: str | Path, *,
                  tsa_url: str = "", tsa_ca_file: str = "") -> dict:
    from cryptography.hazmat.primitives import serialization
    key = _signing_key()
    public_key = key.public_key()
    manifest = {
        "format": "smart-intel-signed-export-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "evidence": evidence,
    }
    payload = json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                         default=str).encode("utf-8")
    signature = key.sign(payload)
    public_pem = public_key.public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    timestamp_data = b""
    timestamp_status = "not_requested"
    if tsa_url.strip():
        openssl = shutil.which("openssl")
        if not openssl:
            raise RuntimeError("OpenSSL is required for RFC 3161 timestamp requests.")
        import requests
        from .network import requests_proxy_map
        with tempfile.TemporaryDirectory(prefix="smartintel-tsa-") as temp:
            temp_dir = Path(temp)
            data_file = temp_dir / "manifest.json"
            query_file = temp_dir / "request.tsq"
            response_file = temp_dir / "response.tsr"
            data_file.write_bytes(payload)
            subprocess.run([openssl, "ts", "-query", "-data", str(data_file), "-sha256",
                            "-cert", "-out", str(query_file)], check=True, capture_output=True, timeout=15)
            response = requests.post(tsa_url.strip(), data=query_file.read_bytes(),
                headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"},
                timeout=20, proxies=requests_proxy_map(), allow_redirects=False)
            response.raise_for_status()
            if len(response.content) > 1024 * 1024:
                raise ValueError("Timestamp response is unexpectedly large.")
            response_file.write_bytes(response.content)
            timestamp_data = response.content
            timestamp_status = "received_unverified"
            if tsa_ca_file.strip():
                subprocess.run([openssl, "ts", "-verify", "-data", str(data_file),
                                "-in", str(response_file), "-CAfile", str(Path(tsa_ca_file).resolve())],
                               check=True, capture_output=True, timeout=15)
                timestamp_status = "verified_against_configured_ca"
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", payload)
        archive.writestr("manifest.ed25519", signature)
        archive.writestr("signing_public_key.pem", public_pem)
        archive.writestr("manifest.sha256", hashlib.sha256(payload).hexdigest() + "\n")
        archive.writestr("timestamp.tsr", timestamp_data)
        archive.writestr("timestamp_status.txt", timestamp_status + "\n")
    return {"path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "manifest_sha256": hashlib.sha256(payload).hexdigest(),
            "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
            "timestamp_status": timestamp_status,
            "signing_note": "Verify the Ed25519 signature against a public key obtained through an independent trusted channel. A TSA response is only trusted when independently validated against a trusted CA."}


def verify_signed_export(path: str | Path, *, tsa_ca_file: str = "") -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    with zipfile.ZipFile(path, "r") as archive:
        payload = archive.read("manifest.json")
        signature = archive.read("manifest.ed25519")
        public_pem = archive.read("signing_public_key.pem")
        timestamp_data = archive.read("timestamp.tsr") if "timestamp.tsr" in archive.namelist() else b""
        recorded_timestamp_status = (archive.read("timestamp_status.txt").decode("utf-8", errors="replace").strip()
                                     if "timestamp_status.txt" in archive.namelist() else "not_present")
        recorded_manifest_hash = (archive.read("manifest.sha256").decode("ascii", errors="replace").strip()
                                  if "manifest.sha256" in archive.namelist() else "")
    digest = hashlib.sha256(payload).hexdigest()
    hash_matches = not recorded_manifest_hash or recorded_manifest_hash == digest
    public_key = serialization.load_pem_public_key(public_pem)
    try:
        public_key.verify(signature, payload)
        valid = bool(hash_matches)
    except InvalidSignature:
        valid = False
    timestamp_result = "not_requested" if not timestamp_data else "received_unverified"
    timestamp_valid = None
    if tsa_ca_file and timestamp_data:
        openssl = shutil.which("openssl")
        if not openssl:
            raise RuntimeError("OpenSSL is required to verify RFC 3161 timestamps.")
        with tempfile.TemporaryDirectory(prefix="smartintel-tsa-verify-") as temp:
            root = Path(temp)
            data_file = root / "manifest.json"
            reply_file = root / "timestamp.tsr"
            data_file.write_bytes(payload)
            reply_file.write_bytes(timestamp_data)
            try:
                subprocess.run([openssl, "ts", "-verify", "-data", str(data_file),
                                "-in", str(reply_file), "-CAfile", str(Path(tsa_ca_file).resolve())],
                               check=True, capture_output=True, timeout=20)
                timestamp_valid = True
                timestamp_result = "verified_against_configured_ca"
            except subprocess.CalledProcessError:
                timestamp_valid = False
                timestamp_result = "verification_failed"
    elif timestamp_data:
        timestamp_result = recorded_timestamp_status or "received_unverified"
    return {
        "valid": valid,
        "sha256": digest,
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
        "manifest_hash_matches": hash_matches,
        "timestamp_status": timestamp_result,
        "timestamp_valid": timestamp_valid,
        "note": "The embedded public key proves internal consistency only. Authenticate its SHA-256 fingerprint independently. A timestamp is trusted only after verification against a trusted TSA CA.",
    }
