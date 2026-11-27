import sqlite3
from datetime import datetime, timezone
from .config import DB_PATH
from .models import Evidence

class Store:
    def __init__(self, path=DB_PATH): self.path=str(path); self._init()
    def connect(self):
        db=sqlite3.connect(self.path); db.row_factory=sqlite3.Row; return db
    def _init(self):
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT DEFAULT '',created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,source TEXT,title TEXT,url TEXT,content TEXT,observed_at TEXT,confidence TEXT,kind TEXT,FOREIGN KEY(case_id) REFERENCES cases(id));''')
    def create_case(self,name,description=''):
        import uuid
        cid=str(uuid.uuid4()); now=datetime.now(timezone.utc).isoformat()
        with self.connect() as db: db.execute('INSERT INTO cases VALUES(?,?,?,?)',(cid,name,description,now))
        return cid
    def cases(self):
        with self.connect() as db: return [dict(r) for r in db.execute('SELECT * FROM cases ORDER BY created_at DESC')]
    def add_evidence(self,e):
        with self.connect() as db: db.execute('INSERT OR REPLACE INTO evidence VALUES(?,?,?,?,?,?,?,?,?)',(e.id,e.case_id,e.source,e.title,e.url,e.content,e.observed_at,e.confidence,e.kind))
    def evidence(self,cid):
        with self.connect() as db: return [Evidence(**dict(r)) for r in db.execute('SELECT * FROM evidence WHERE case_id=? ORDER BY observed_at DESC',(cid,))]
