"""SQLite case store with encrypted evidence payloads and persisted audit events."""
import base64
import hashlib
import json
import sqlite3
import re
from datetime import datetime, timezone
from pathlib import Path
from .config import DB_PATH, APP_DIR
from .models import Evidence
from . import secure_vault, database_encryption


class Store:
    def __init__(self, path=DB_PATH):
        self.path = str(path)
        self._init()

    def connect(self):
        if database_encryption.database_encryption_enabled():
            db = database_encryption.encrypted_connect(self.path)
        else:
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
                CREATE TABLE IF NOT EXISTS vault_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS vault_attachments(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,filename TEXT NOT NULL,kind TEXT NOT NULL,path TEXT NOT NULL,size INTEGER NOT NULL,sha256 TEXT NOT NULL,ciphertext_sha256 TEXT NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(case_id) REFERENCES cases(id));
                CREATE TABLE IF NOT EXISTS audit_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT,created_at TEXT NOT NULL,event_json TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS graph_aliases(case_id TEXT NOT NULL,alias_node_id TEXT NOT NULL,canonical_node_id TEXT NOT NULL,created_at TEXT NOT NULL,created_by TEXT DEFAULT '',PRIMARY KEY(case_id,alias_node_id),FOREIGN KEY(case_id) REFERENCES cases(id));
                CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL,created_at TEXT NOT NULL,disabled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS case_members(case_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(case_id,user_id),FOREIGN KEY(case_id) REFERENCES cases(id),FOREIGN KEY(user_id) REFERENCES users(id));
                CREATE TABLE IF NOT EXISTS monitor_schedules(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,target TEXT NOT NULL,interval_seconds INTEGER NOT NULL,next_run_at TEXT NOT NULL,enabled INTEGER NOT NULL,created_by TEXT NOT NULL,last_run_at TEXT,last_status TEXT DEFAULT '',created_at TEXT NOT NULL,FOREIGN KEY(case_id) REFERENCES cases(id),FOREIGN KEY(created_by) REFERENCES users(id));
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
                CREATE INDEX IF NOT EXISTS idx_attachments_case ON vault_attachments(case_id);
                CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id,seq);
            """)

    def create_case(self, name, description='', owner_id=None):
        import uuid
        cid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute('INSERT INTO cases VALUES(?,?,?,?)', (cid, name, description, now))
        if owner_id:
            self.add_case_member(cid, owner_id, "owner")
        self.append_event(cid, {"action": "case_created", "case_id": cid, "name": name})
        return cid

    def cases(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM cases ORDER BY created_at DESC')]

    def create_user(self, username, password, role="analyst"):
        import uuid, hashlib, secrets
        name = (username or "").strip()
        if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("Username must use 1-64 letters, numbers, dots, underscores or hyphens.")
        if len(password or "") < 12 or len(password) > 256:
            raise ValueError("Password must be 12-256 characters.")
        if role not in {"admin", "analyst", "viewer"}:
            raise ValueError("Role must be admin, analyst or viewer.")
        user_id = str(uuid.uuid4())
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
        stored = base64.b64encode(salt + digest).decode("ascii")
        with self.connect() as db:
            db.execute("INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                       (user_id, name, stored, role, datetime.now(timezone.utc).isoformat()))
        self.append_event(None, {"action": "user_created", "user_id": user_id, "username": name, "role": role})
        return user_id

    def users_count(self):
        with self.connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def authenticate_user(self, username, password):
        import hashlib, hmac
        with self.connect() as db:
            row = db.execute("SELECT * FROM users WHERE username=? AND disabled=0",
                             ((username or "").strip(),)).fetchone()
        if row is None:
            hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), b"\0" * 16, 310000)
            return None
        try:
            packed = base64.b64decode(row["password_hash"])
            salt, expected = packed[:16], packed[16:]
            actual = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, 310000)
            if hmac.compare_digest(actual, expected):
                return {"id": row["id"], "username": row["username"], "role": row["role"]}
        except Exception:
            return None
        return None

    def list_users(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT id,username,role,disabled,created_at FROM users ORDER BY username")]

    def set_user_disabled(self, user_id, disabled=True):
        with self.connect() as db:
            db.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, user_id))
        self.append_event(None, {"action": "user_access_changed", "user_id": user_id, "disabled": bool(disabled)})

    def add_case_member(self, case_id, user_id, role="analyst"):
        if role not in {"owner", "analyst", "viewer"}:
            raise ValueError("Case role must be owner, analyst or viewer.")
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise KeyError("Unknown case.")
            if not db.execute("SELECT 1 FROM users WHERE id=? AND disabled=0", (user_id,)).fetchone():
                raise KeyError("Unknown or disabled user.")
            db.execute("INSERT OR REPLACE INTO case_members(case_id,user_id,role,created_at) VALUES(?,?,?,?)",
                       (case_id, user_id, role, datetime.now(timezone.utc).isoformat()))
        self.append_event(case_id, {"action": "case_member_added", "user_id": user_id, "role": role})

    def case_members(self, case_id):
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT u.id,u.username,u.role AS account_role,m.role AS case_role FROM case_members m JOIN users u ON u.id=m.user_id WHERE m.case_id=? ORDER BY u.username",
                (case_id,))]

    def cases_for_user(self, user):
        if not user or user.get("role") == "admin":
            return self.cases()
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT c.* FROM cases c JOIN case_members m ON m.case_id=c.id WHERE m.user_id=? ORDER BY c.created_at DESC",
                (user["id"],))]

    def user_case_role(self, case_id, user):
        if not user or user.get("role") == "admin":
            return "owner"
        with self.connect() as db:
            row = db.execute("SELECT role FROM case_members WHERE case_id=? AND user_id=?",
                             (case_id, user["id"])).fetchone()
        return row["role"] if row else None

    def add_graph_alias(self, case_id, alias_node_id, canonical_node_id, created_by=""):
        if alias_node_id == canonical_node_id:
            raise ValueError("A graph node cannot be merged into itself.")
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO graph_aliases(case_id,alias_node_id,canonical_node_id,created_at,created_by) VALUES(?,?,?,?,?)",
                       (case_id, alias_node_id, canonical_node_id, datetime.now(timezone.utc).isoformat(), created_by))
        self.append_event(case_id, {"action": "graph_alias_merged", "alias_node_id": alias_node_id,
                                    "canonical_node_id": canonical_node_id, "created_by": created_by})

    def graph_aliases(self, case_id):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM graph_aliases WHERE case_id=?", (case_id,))]

    def add_monitor_schedule(self, case_id, target, interval_seconds, created_by):
        import uuid
        if int(interval_seconds) < 3600 or int(interval_seconds) > 30 * 86400:
            raise ValueError("Monitoring interval must be between 1 hour and 30 days.")
        value = (target or "").strip()
        if not value:
            raise ValueError("Monitoring target is required.")
        now = datetime.now(timezone.utc)
        schedule_id = str(uuid.uuid4())
        with self.connect() as db:
            db.execute("INSERT INTO monitor_schedules(id,case_id,target,interval_seconds,next_run_at,enabled,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                       (schedule_id, case_id, value, int(interval_seconds), now.isoformat(), 1, created_by, now.isoformat()))
        self.append_event(case_id, {"action": "monitor_schedule_created", "schedule_id": schedule_id,
                                    "target": value, "interval_seconds": int(interval_seconds)})
        return schedule_id

    def due_monitor_schedules(self, now=None):
        stamp = (now or datetime.now(timezone.utc)).isoformat()
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT * FROM monitor_schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at",
                (stamp,))]

    def monitor_schedules(self, case_id=None):
        with self.connect() as db:
            if case_id:
                rows = db.execute("SELECT * FROM monitor_schedules WHERE case_id=? ORDER BY created_at DESC", (case_id,))
            else:
                rows = db.execute("SELECT * FROM monitor_schedules ORDER BY created_at DESC")
            return [dict(row) for row in rows]

    def update_monitor_schedule(self, schedule_id, *, next_run_at=None, enabled=None, status=None):
        with self.connect() as db:
            if next_run_at is not None:
                db.execute("UPDATE monitor_schedules SET next_run_at=? WHERE id=?", (next_run_at, schedule_id))
            if enabled is not None:
                db.execute("UPDATE monitor_schedules SET enabled=? WHERE id=?", (1 if enabled else 0, schedule_id))
            if status is not None:
                db.execute("UPDATE monitor_schedules SET last_run_at=?,last_status=? WHERE id=?",
                           (datetime.now(timezone.utc).isoformat(), str(status)[:500], schedule_id))

    def remove_monitor_schedule(self, schedule_id):
        with self.connect() as db:
            row = db.execute("SELECT case_id FROM monitor_schedules WHERE id=?", (schedule_id,)).fetchone()
            db.execute("DELETE FROM monitor_schedules WHERE id=?", (schedule_id,))
        if row:
            self.append_event(row["case_id"], {"action": "monitor_schedule_removed", "schedule_id": schedule_id})

    def _vault_configured(self):
        with self.connect() as db:
            row = db.execute("SELECT value FROM vault_settings WHERE key='enabled'").fetchone()
        return bool(row and row["value"] == "1")

    def _encode_content(self, content):
        if not self._vault_configured():
            return content
        # Fail closed if the OS credential store is unavailable or the key was lost.
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
        if self._vault_configured() and not secure_vault.vault_enabled():
            raise RuntimeError("Vault key is unavailable. Refusing to generate a replacement key because existing evidence would become unrecoverable.")
        secure_vault.enable_vault()
        with self.connect() as db:
            rows = db.execute("SELECT id,content FROM evidence").fetchall()
            for row in rows:
                value = row["content"] or ""
                if not (isinstance(value, str) and value.startswith("SIENC1:")):
                    token = secure_vault.encrypt(value.encode("utf-8"))
                    db.execute("UPDATE evidence SET content=? WHERE id=?",
                               ("SIENC1:" + base64.b64encode(token).decode("ascii"), row["id"]))
            db.execute("INSERT OR REPLACE INTO vault_settings(key,value) VALUES('enabled','1')")
        self.append_event(None, {"action":"evidence_payload_encryption_enabled","scope":"all_cases"})

    def enable_database_encryption(self):
        """Migrate this case database to SQLCipher; preserve a plaintext backup."""
        result = database_encryption.encrypt_database(self.path)
        self._init()
        self.append_event(None, {"action": "full_database_encryption_enabled", "algorithm": result["algorithm"]})
        return result

    def vault_status(self):
        configured = self._vault_configured()
        key_available = secure_vault.vault_enabled() if configured else False
        return {"enabled": configured, "unlocked": key_available, "locked": configured and not key_available,
                "scope":"evidence content and attachment payloads; case metadata remains plaintext"}

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
