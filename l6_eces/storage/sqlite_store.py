import os
import sqlite3
import json
import threading
from typing import Optional, List, Dict, Any

from l6_eces.chain.schemas import EvidenceRecord, GenesisRecord, ChainHead
from l6_eces.chain.store import EvidenceStore

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, ".data", "evidence", "eces.db")

class SQLiteEvidenceStore(EvidenceStore):
    """
    Append-only durable evidence store using SQLite3.
    Enforces application-level append-only constraints and DB-level Unique constraints.
    """
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or os.environ.get("AGENTSENTINEL_ECES_DB_PATH", DEFAULT_DB_PATH)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._lock:
            conn = self._get_connection()
            try:
                # Genesis table
                conn.execute("""
                CREATE TABLE IF NOT EXISTS genesis (
                    chain_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    genesis_hash TEXT NOT NULL,
                    record_json TEXT NOT NULL
                )
                """)
                # Evidence table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS evidence (
                        chain_id TEXT NOT NULL,
                        sequence_number INTEGER NOT NULL,
                        session_id TEXT NOT NULL,
                        event_id TEXT NOT NULL UNIQUE,
                        timestamp_ns INTEGER NOT NULL,
                        source_layer TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        record_json TEXT NOT NULL,
                        PRIMARY KEY (chain_id, sequence_number)
                    )
                """)
                # Index for session retrieval
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_session_id ON evidence(session_id)
                """)
                conn.commit()
            finally:
                conn.close()

    def append_genesis(self, record: GenesisRecord):
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute("SELECT COUNT(*) FROM genesis")
                if cursor.fetchone()[0] > 0:
                    raise RuntimeError("Cannot append genesis to non-empty chain")
                
                # Using model_dump_json for exact structural preservation
                record_json = record.model_dump_json()
                
                conn.execute(
                    "INSERT INTO genesis (chain_id, created_at, genesis_hash, record_json) VALUES (?, ?, ?, ?)",
                    (record.chain_id, record.created_at, record.genesis_hash, record_json)
                )
                conn.commit()
            finally:
                conn.close()

    def append(self, record: EvidenceRecord):
        with self._lock:
            conn = self._get_connection()
            try:
                record_json = record.model_dump_json()
                
                conn.execute(
                    """
                    INSERT INTO evidence 
                    (chain_id, sequence_number, session_id, event_id, timestamp_ns, source_layer, event_type, previous_hash, event_hash, record_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.chain_id, record.sequence_number, record.session_id, record.event_id, 
                        record.timestamp_ns, record.source_layer, record.event_type, 
                        record.previous_hash, record.event_hash, record_json
                    )
                )
                conn.commit()
            finally:
                conn.close()

    def read_all(self) -> List[Dict[str, Any]]:
        records = []
        conn = self._get_connection()
        try:
            # Get genesis
            cursor = conn.execute("SELECT record_json FROM genesis ORDER BY created_at ASC")
            for row in cursor.fetchall():
                records.append({
                    "_type": "genesis",
                    "data": json.loads(row[0])
                })
            
            # Get evidence ordered by sequence
            cursor = conn.execute("SELECT record_json FROM evidence ORDER BY sequence_number ASC")
            for row in cursor.fetchall():
                records.append({
                    "_type": "evidence",
                    "data": json.loads(row[0])
                })
        finally:
            conn.close()
        return records

    def get_chain_head(self) -> Optional[ChainHead]:
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT record_json FROM evidence ORDER BY sequence_number DESC LIMIT 1")
            row = cursor.fetchone()
            
            if row:
                last_evidence = json.loads(row[0])
                return ChainHead(
                    chain_id=last_evidence["chain_id"],
                    latest_sequence=last_evidence["sequence_number"],
                    latest_event_hash=last_evidence["event_hash"],
                    updated_at=last_evidence["timestamp_ns"],
                    segment_id="1"
                )
            
            # Fallback to genesis if no evidence
            cursor = conn.execute("SELECT record_json FROM genesis ORDER BY created_at DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                genesis = json.loads(row[0])
                return ChainHead(
                    chain_id=genesis["chain_id"],
                    latest_sequence=0,
                    latest_event_hash=genesis["genesis_hash"],
                    updated_at=genesis["created_at"],
                    segment_id="1"
                )
                
        finally:
            conn.close()
        return None
