"""Tamper-evident audit journal, attachment hashing and optional authenticated encryption."""
import hashlib,json,os
from datetime import datetime,timezone
from pathlib import Path
def sha256_file(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()
def append_audit(journal,event):
    p=Path(journal); p.parent.mkdir(parents=True,exist_ok=True); previous="0"*64
    if p.exists():
        valid,count=verify_audit(p)
        if not valid: raise ValueError(f"Audit journal is invalid after {count} verified entries; refusing to append.")
        lines=[x for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
        if lines: previous=json.loads(lines[-1])["entry_hash"]
    body={"timestamp":datetime.now(timezone.utc).isoformat(),"previous_hash":previous,"event":event}
    body["entry_hash"]=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    with p.open("a",encoding="utf-8") as f: f.write(json.dumps(body,ensure_ascii=False)+"\n"); f.flush(); os.fsync(f.fileno())
    return body
def verify_audit(journal):
    p=Path(journal); previous="0"*64; count=0
    if not p.exists(): return True,0
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        try:
            item=json.loads(line); claimed=item.pop("entry_hash",None)
            if item.get("previous_hash")!=previous: return False,count
            actual=hashlib.sha256(json.dumps(item,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
            if claimed!=actual: return False,count
            previous=claimed; count+=1
        except (ValueError,TypeError,KeyError,AttributeError):
            return False,count
    return True,count
def generate_encryption_key():
    from cryptography.fernet import Fernet
    return Fernet.generate_key()
def encrypt_bytes(data,key):
    from cryptography.fernet import Fernet
    return Fernet(key).encrypt(data)
def sign_manifest(manifest,private_key_pem,password=None):
    from cryptography.hazmat.primitives import serialization
    key=serialization.load_pem_private_key(private_key_pem,password=password)
    return key.sign(manifest)
