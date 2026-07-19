"""
db_registry.py — DB-1: Evidence registry (pcap_registry.db).
Write-once at upload time. Never modified by the analysis pipeline.
"""
import sqlite3
import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
REGISTRY_DB_PATH = os.path.join(BASE_DIR, 'pcap_registry.db')


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(REGISTRY_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_registry_db():
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pcap_uploads (
            upload_id   TEXT PRIMARY KEY,
            filename    TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            size_bytes  INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'registered'
        )
    """)
    conn.commit()
    conn.close()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def register_upload(filename: str, stored_path: str) -> Dict[str, Any]:
    """Compute hash, insert row, return the full record."""
    upload_id = str(uuid.uuid4())
    digest = sha256_file(stored_path)
    size = os.path.getsize(stored_path)
    uploaded_at = datetime.now(timezone.utc).isoformat()

    conn = _connect()
    conn.execute(
        """INSERT INTO pcap_uploads
           (upload_id, filename, stored_path, sha256_hash, size_bytes, uploaded_at, status)
           VALUES (?, ?, ?, ?, ?, ?, 'registered')""",
        (upload_id, filename, stored_path, digest, size, uploaded_at)
    )
    conn.commit()
    conn.close()

    return {
        'upload_id': upload_id,
        'filename': filename,
        'stored_path': stored_path,
        'sha256_hash': digest,
        'size_bytes': size,
        'uploaded_at': uploaded_at,
        'status': 'registered',
    }


def get_upload(upload_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM pcap_uploads WHERE upload_id = ?", (upload_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_uploads() -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM pcap_uploads ORDER BY uploaded_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_status(upload_id: str, status: str):
    """Allowed transitions: registered -> filtered -> analyzed."""
    conn = _connect()
    conn.execute(
        "UPDATE pcap_uploads SET status = ? WHERE upload_id = ?",
        (status, upload_id)
    )
    conn.commit()
    conn.close()
