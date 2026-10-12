import os
import sqlite3
import json
from typing import List, Optional

from dashboard_api.schemas.evidence import SessionListItem, SessionListResponse, ChainRecord, SessionDetailResponse, VerifyResponse
from dashboard_api.schemas.common import ExecutionMode
from l6_eces.storage.sqlite_store import SQLiteEvidenceStore, DEFAULT_DB_PATH
from l6_eces.forensics.verifier import EvidenceVerifier

class EvidenceService:
    def __init__(self, db_path: str | None = None):
        self._db_path = db_path

    @property
    def db_path(self) -> str:
        return self._db_path or os.environ.get("AGENTSENTINEL_ECES_DB_PATH", DEFAULT_DB_PATH)

    @db_path.setter
    def db_path(self, value: str) -> None:
        self._db_path = value
        
    def get_sessions(self) -> SessionListResponse:
        if not os.path.exists(self.db_path):
            return SessionListResponse(sessions=[])
            
        sessions = []
        conn = sqlite3.connect(self.db_path)
        try:
            # Query unique sessions and their event counts / min timestamps
            cursor = conn.execute("""
                SELECT session_id, count(*), min(timestamp_ns)
                FROM evidence 
                GROUP BY session_id
                ORDER BY min(timestamp_ns) DESC
            """)
            
            for row in cursor.fetchall():
                sessions.append(SessionListItem(
                    session_id=row[0],
                    event_count=row[1],
                    start_time_ns=row[2],
                    execution_mode=ExecutionMode.SIMULATED
                ))
        finally:
            conn.close()
                
        return SessionListResponse(sessions=sessions)
        
    def get_session_chain(self, session_id: str) -> Optional[SessionDetailResponse]:
        if not os.path.exists(self.db_path):
            return None
            
        chain = []
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("""
                SELECT sequence_number, timestamp_ns, event_type, source_layer, event_id, previous_hash, event_hash, record_json
                FROM evidence
                WHERE session_id = ?
                ORDER BY sequence_number ASC
            """, (session_id,))
            
            rows = cursor.fetchall()
            if not rows:
                return None
                
            for row in rows:
                chain.append(ChainRecord(
                    sequence_number=row[0],
                    timestamp_ns=row[1],
                    event_type=row[2],
                    source_layer=row[3],
                    event_id=row[4],
                    previous_hash=row[5],
                    event_hash=row[6],
                    payload=json.loads(row[7])
                ))
        finally:
            conn.close()
                
        return SessionDetailResponse(session_id=session_id, execution_mode=ExecutionMode.SIMULATED, chain=chain)

    def verify_session(self, session_id: str) -> VerifyResponse:
        if not os.path.exists(self.db_path):
            return VerifyResponse(session_id=session_id, valid=False, records_checked=0, failure="DB_NOT_FOUND", execution_mode=ExecutionMode.SIMULATED)
            
        store = SQLiteEvidenceStore(self.db_path)
        records = store.read_all()
        # The research replay uses ephemeral per-run signing keys without a retained
        # public-key registry. Verify the global hash chain, but do not claim that
        # signatures can be authenticated. Gateway receipts have separate real checks.
        result = EvidenceVerifier(None).verify_chain(records, verify_signatures=False)
        hash_chain_valid = result.valid
        return VerifyResponse(
            session_id=session_id,
            valid=False,
            hash_chain_valid=hash_chain_valid,
            signature_status="UNVERIFIED_KEY_UNAVAILABLE" if hash_chain_valid else "NOT_CHECKED",
            records_checked=result.records_checked,
            failure="SIGNATURE_KEY_UNAVAILABLE" if hash_chain_valid else result.failure_type,
            execution_mode=ExecutionMode.SIMULATED
        )
