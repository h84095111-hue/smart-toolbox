"""SQLite case store with encrypted evidence payloads and persisted audit events."""
import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .config import DB_PATH, APP_DIR
from .models import Evidence
from . import secure_vault


class Store:
    def __init__(self, path=DB_PATH):
        self.path = str(path)
        self._init()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def _init(self):
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT DEFAULT '',created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,source TEXT,title TEXT,url TEXT,content TEXT,observed_at TEXT,confidence TEXT,kind TEXT,FOREIGN KEY(case_id) REFERENCES cases(id));
                CREATE TABLE IF NOT EXISTS vault_attachments(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,filename TEXT NOT NULL,kind TEXT NOT NULL,path TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,ciphertext_sha256 TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(case_id) REFERENCES cases(id));
                CREATE TABLE IF NOT EXISTS audit_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT,created_at TEXT NOT NULL,event_json TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
                CREATE INDEX IF NOT EXISTS idx_attachments_case ON vault_attachments(case_id);
                CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id,seq);
            """)

    def create_case(self, name, description=''):
        import uuid
        cid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute('INSERT INTO cases VALUES(?,?,?,?)', (cid, name, description, now))
        self.append_event(cid, {"action": "case_created", "case_id": cid, "name": name})
        return cid

    def cases(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM cases ORDER BY created_at DESC')]

    @staticmethod
    def _encode_content(content):
        if not secure_vault.vault_enabled():
            return content
        token = secure_vault.encrypt((content or "").encode("utf-8"))
        return "SIENC1:" + base64.b64encode(token).decode("ascii")

    @staticmethod
    def _decode_content(content):
        if isinstance(content, str) and content.startswith("SIENC1:"):
            token = base64.b64decode(content[7:].encode("ascii"), validate=True)
            return secure_vault.decrypt(token).decode("utf-8")
        return content or ""

    def add_evidence(self, e):
        encoded = self._encode_content(e.content)
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO evidence VALUES(?,?,?,?,?,?,?,?,?)',
                       (e.id,e.case_id,e.source,e.title,e.url,encoded,e.observed_at,e.confidence,e.kind))
        self.append_event(e.case_id, {"action":"evidence_added","evidence_id":e.id,"source":e.source,"title":e.title})

    def evidence(self, cid):
        with self.connect() as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM evidence WHERE case_id=? ORDER BY observed_at DESC',(cid,))]
        for row in rows:
            row["content"] = self._decode_content(row.get("content"))
        return [Evidence(**row) for row in rows]

    def enable_evidence_encryption(self):
        secure_vault.enable_vault()
        with self.connect() as db:
            rows = db.execute("SELECT id,content FROM evidence").fetchall()
            for row in rows:
                value = row["content"] or ""
                if not (isinstance(value, str) and value.startswith("SIENC1:")):
                    token = secure_vault.encrypt(value.encode("utf-8"))
                    db.execute("UPDATE evidence SET content=? WHERE id=?",
                               ("SIENC1:" + base64.b64encode(token).decode("ascii"), row["id"]))
        self.append_event(None, {"action":"evidence_payload_encryption_enabled","scope":"all_cases"})

    def vault_status(self):
        return {"enabled": secure_vault.vault_enabled(), "scope":"evidence content and attachment payloads; case metadata remains plaintext"}

    def add_attachment(self, case_id, source_path, kind="attachment"):
        row = secure_vault.import_attachment(APP_DIR, case_id, source_path, kind=kind)
        with self.connect() as db:
            db.execute("""INSERT INTO vault_attachments
                (id,case_id,filename,kind,path,size,sha256,ciphertext_sha256,created_at)
                VALUES(:id,:case_id,:filename,:kind,:path,:size,:sha256,:ciphertext_sha256,:created_at)""", row)
        self.append_event(case_id, {"action":"attachment_added","attachment_id":row["id"],"filename":row["filename"],"kind":kind,"sha256":row["sha256"],"size":row["size"]})
        return row

    def attachments(self, case_id):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM vault_attachments WHERE case_id=? ORDER BY created_at DESC",(case_id,))]

    def read_attachment(self, attachment_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM vault_attachments WHERE id=?",(attachment_id,)).fetchone()
        if row is None:
            raise KeyError(attachment_id)
        return secure_vault.read_attachment(dict(row))

    def append_event(self, case_id, event):
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(event, sort_keys=True, separators=(",",":"), ensure_ascii=False)
        with self.connect() as db:
            previous = db.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            previous_hash = previous["event_hash"] if previous else "0" * 64
            body = {"case_id":case_id,"created_at":now,"event_json":payload,"previous_hash":previous_hash}
            digest = hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")).hexdigest()
            db.execute("INSERT INTO audit_events(case_id,created_at,event_json,previous_hash,event_hash) VALUES(?,?,?,?,?)",
                       (case_id,now,payload,previous_hash,digest))
        return digest

    def workflow_events(self, case_id, run_id, events):
        for event in events:
            self.append_event(case_id, {"action":"workflow_event","run_id":run_id,"event":event})

    def verify_event_chain(self):
        previous = "0" * 64
        count = 0
        with self.connect() as db:
            rows = db.execute("SELECT case_id,created_at,event_json,previous_hash,event_hash FROM audit_events ORDER BY seq").fetchall()
        for row in rows:
            body = {"case_id":row["case_id"],"created_at":row["created_at"],"event_json":row["event_json"],"previous_hash":row["previous_hash"]}
            digest = hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous or row["event_hash"] != digest:
                return False, count
            previous = digest
            count += 1
        return True, count
