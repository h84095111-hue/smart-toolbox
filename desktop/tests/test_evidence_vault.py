from pathlib import Path

from smartintel.storage import Store
from smartintel.models import Evidence


def test_event_chain_detects_tampering(tmp_path):
    store = Store(tmp_path / "case.sqlite3")
    case_id = store.create_case("Vault test")
    store.append_event(case_id, {"action": "workflow_started", "run_id": "r1"})
    assert store.verify_event_chain() == (True, 2)
    with store.connect() as db:
        db.execute("UPDATE audit_events SET event_json=? WHERE seq=2", ('{"action":"edited"}',))
    ok, count = store.verify_event_chain()
    assert not ok
    assert count == 1


def test_workflow_events_are_persisted(tmp_path):
    store = Store(tmp_path / "case.sqlite3")
    case_id = store.create_case("Workflow audit")
    events = [{"type": "workflow_started"}, {"type": "collector_completed", "collector": "crtsh"}]
    store.workflow_events(case_id, "run-123", events)
    assert store.verify_event_chain() == (True, 3)
    with store.connect() as db:
        rows = db.execute("SELECT event_json FROM audit_events WHERE case_id=? ORDER BY seq", (case_id,)).fetchall()
    assert '"workflow_event"' in rows[1]["event_json"]
    assert '"run-123"' in rows[2]["event_json"]


def test_evidence_content_encryption_round_trip(tmp_path, monkeypatch):
    store = Store(tmp_path / "encrypted.sqlite3")
    case_id = store.create_case("Encrypted")
    store.add_evidence(Evidence(case_id, "test", "secret", content="private evidence"))
    monkeypatch.setattr(store, "_vault_configured", lambda: True)
    monkeypatch.setattr("smartintel.storage.secure_vault.encrypt", lambda b: b"cipher:" + b)
    monkeypatch.setattr("smartintel.storage.secure_vault.decrypt", lambda b: b.removeprefix(b"cipher:"))
    store.add_evidence(Evidence(case_id, "test", "encrypted", content="new private evidence"))
    with store.connect() as db:
        raw = db.execute("SELECT content FROM evidence WHERE title='encrypted'").fetchone()["content"]
    assert raw.startswith("SIENC1:")
    assert store.evidence(case_id)[0].content == "new private evidence"


def test_vault_migration_encrypts_existing_evidence(tmp_path, monkeypatch):
    store = Store(tmp_path / "migration.sqlite3")
    case_id = store.create_case("Migration")
    store.add_evidence(Evidence(case_id, "test", "before", content="plaintext"))
    monkeypatch.setattr("smartintel.storage.secure_vault.enable_vault", lambda: None)
    monkeypatch.setattr("smartintel.storage.secure_vault.encrypt", lambda b: b"encrypted:" + b)
    monkeypatch.setattr("smartintel.storage.secure_vault.vault_enabled", lambda: True)
    monkeypatch.setattr("smartintel.storage.secure_vault.decrypt", lambda b: b.removeprefix(b"encrypted:"))
    store.enable_evidence_encryption()
    with store.connect() as db:
        raw = db.execute("SELECT content FROM evidence WHERE title='before'").fetchone()["content"]
    assert raw.startswith("SIENC1:")
    assert store.evidence(case_id)[0].content == "plaintext"


def test_missing_key_does_not_overwrite_existing_vault(tmp_path, monkeypatch):
    store = Store(tmp_path / "locked.sqlite3")
    monkeypatch.setattr(store, "_vault_configured", lambda: True)
    monkeypatch.setattr("smartintel.storage.secure_vault.vault_enabled", lambda: False)
    called = []
    monkeypatch.setattr("smartintel.storage.secure_vault.enable_vault", lambda: called.append(True))
    import pytest
    with pytest.raises(RuntimeError, match="Refusing to generate a replacement key"):
        store.enable_evidence_encryption()
    assert called == []


def test_attachment_vault_round_trip_and_hash_verification(tmp_path, monkeypatch):
    from smartintel import secure_vault
    source = tmp_path / "screen.png"
    source.write_bytes(b"fake-png-bytes")
    monkeypatch.setattr(secure_vault, "encrypt", lambda data: b"cipher:" + data)
    monkeypatch.setattr(secure_vault, "decrypt", lambda data: data.removeprefix(b"cipher:"))
    row = secure_vault.import_attachment(tmp_path / "vault-root", "case-1", source, kind="screenshot")
    assert row["kind"] == "screenshot"
    assert secure_vault.read_attachment(row) == b"fake-png-bytes"
    Path(row["path"]).write_bytes(b"tampered")
    import pytest
    with pytest.raises(ValueError, match="ciphertext hash mismatch"):
        secure_vault.read_attachment(row)


def test_local_file_can_be_wrapped_as_warc_resource(tmp_path):
    from smartintel.secure_vault import make_warc_record
    source = tmp_path / "capture.txt"
    source.write_text("captured evidence", encoding="utf-8")
    record = make_warc_record(source)
    assert record.startswith(b"WARC/1.1\r\n")
    assert b"WARC-Type: resource" in record
    assert b"captured evidence" in record
