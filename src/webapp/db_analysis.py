"""
db_analysis.py — DB-2: Derived analysis data (whatsapp_analysis.db).
Fully recomputable from the original pcap via the pipeline.
Joined to DB-1 via upload_id in application code only.
"""
import sqlite3
import os
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
ANALYSIS_DB_PATH = os.path.join(BASE_DIR, 'whatsapp_analysis.db')


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(ANALYSIS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_analysis_db():
    conn = _connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS whatsapp_packets (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            upload_id           TEXT NOT NULL,
            packet_no           INTEGER NOT NULL,
            timestamp           REAL NOT NULL,
            src_ip              TEXT,
            dst_ip              TEXT,
            src_port            INTEGER,
            dst_port            INTEGER,
            protocol            TEXT,
            length              INTEGER,
            flow_id             TEXT,
            whatsapp_confidence TEXT NOT NULL,
            whatsapp_media_guess TEXT,
            sub_activity        TEXT,
            ip_ttl              INTEGER,
            is_stun_binding     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS parties (
            party_id      TEXT PRIMARY KEY,
            upload_id     TEXT NOT NULL,
            remote_ip     TEXT NOT NULL,
            remote_port   INTEGER,
            protocol      TEXT NOT NULL,
            local_ips     TEXT,
            packet_count  INTEGER NOT NULL,
            total_bytes   INTEGER NOT NULL,
            first_seen    REAL NOT NULL,
            last_seen     REAL NOT NULL,
            duration_s    REAL NOT NULL,
            party_type    TEXT NOT NULL,
            sub_activity  TEXT,
            confidence    TEXT,
            os_hint       TEXT
        );

        CREATE TABLE IF NOT EXISTS geo_cache (
            ip           TEXT PRIMARY KEY,
            country      TEXT,
            city         TEXT,
            latitude     REAL,
            longitude    REAL,
            asn          TEXT,
            asn_org      TEXT,
            looked_up_at REAL,
            rdns_hostname TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_packets_upload ON whatsapp_packets(upload_id);
        CREATE INDEX IF NOT EXISTS idx_parties_upload ON parties(upload_id);
    """)
    conn.commit()
    conn.close()


def insert_whatsapp_packets(upload_id: str, packets: List[Dict[str, Any]]):
    """Insert classified packets. Deduplicates by upload_id before inserting."""
    conn = _connect()
    conn.execute("DELETE FROM whatsapp_packets WHERE upload_id = ?", (upload_id,))

    packets_sorted = sorted(packets, key=lambda p: p['timestamp'])
    # Cap at 500 per upload for prototype performance
    if len(packets_sorted) > 500:
        packets_sorted = packets_sorted[:500]

    conn.executemany(
        """INSERT INTO whatsapp_packets
           (upload_id, packet_no, timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, length, flow_id, whatsapp_confidence, whatsapp_media_guess,
            sub_activity, ip_ttl, is_stun_binding)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                upload_id, p.get('packet_no'), p.get('timestamp'),
                p.get('src_ip'), p.get('dst_ip'),
                p.get('src_port'), p.get('dst_port'),
                p.get('protocol'), p.get('length'),
                p.get('flow_id'), p.get('whatsapp_confidence'),
                p.get('whatsapp_media_guess'), p.get('sub_activity'),
                p.get('ip_ttl'), 1 if p.get('is_stun_binding') else 0
            )
            for p in packets_sorted
        ]
    )
    conn.commit()
    count = conn.execute(
        "SELECT COUNT(1) FROM whatsapp_packets WHERE upload_id = ?", (upload_id,)
    ).fetchone()[0]
    conn.close()
    return count


def insert_parties(upload_id: str, parties: List[Dict[str, Any]]):
    conn = _connect()
    conn.execute("DELETE FROM parties WHERE upload_id = ?", (upload_id,))
    conn.executemany(
        """INSERT OR REPLACE INTO parties
           (party_id, upload_id, remote_ip, remote_port, protocol,
            local_ips, packet_count, total_bytes, first_seen, last_seen,
            duration_s, party_type, sub_activity, confidence, os_hint)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                p['party_id'], upload_id, p['remote_ip'], p.get('remote_port'),
                p['protocol'], p.get('local_ips', ''),
                p['packet_count'], p['total_bytes'],
                p['first_seen'], p['last_seen'], p.get('duration_s', 0.0),
                p['party_type'], p.get('sub_activity'), p.get('confidence'),
                p.get('os_hint')
            )
            for p in parties
        ]
    )
    conn.commit()
    conn.close()


def get_packets(upload_id: str) -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM whatsapp_packets WHERE upload_id = ? ORDER BY timestamp",
        (upload_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_parties(upload_id: str) -> List[Dict[str, Any]]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM parties WHERE upload_id = ? ORDER BY packet_count DESC",
        (upload_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_geo(ip: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    row = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return dict(row) if row else None


def upsert_geo(ip: str, data: Dict[str, Any]):
    conn = _connect()
    conn.execute(
        """INSERT OR REPLACE INTO geo_cache
           (ip, country, city, latitude, longitude, asn, asn_org, looked_up_at, rdns_hostname)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (ip, data.get('country'), data.get('city'),
         data.get('latitude'), data.get('longitude'),
         data.get('asn'), data.get('asn_org'),
         data.get('looked_up_at'), data.get('rdns_hostname'))
    )
    conn.commit()
    conn.close()
