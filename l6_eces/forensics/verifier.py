import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from l6_eces.crypto.hasher import HashProvider, CanonicalSerializer
from l6_eces.crypto.signer import HardwareSigner

class VerificationResult(BaseModel):
    valid: bool
    records_checked: int
    first_failure_sequence: Optional[int] = None
    failure_type: Optional[str] = None
    failure_event_id: Optional[str] = None
    head_hash: Optional[str] = None
    signature_status: str
    schema_status: str

class EvidenceVerifier:
    """Offline and online evidence chain verifier."""
    
    def __init__(self, signer: Optional[HardwareSigner]):
        # We need the signer to verify signatures (it acts as a public key provider here).
        # In a real offline tool, this would be a public key registry.
        self.signer = signer
        self.hasher = HashProvider() # Detects BLAKE3 or SHA-256
        
    def verify_chain(self, records: List[Dict[str, Any]], verify_signatures: bool = True) -> VerificationResult:
        """
        Verifies a list of records (genesis + evidence) for integrity.
        records must be ordered by sequence.
        """
        if not records:
            return VerificationResult(
                valid=False, records_checked=0,
                failure_type="EMPTY_CHAIN",
                signature_status="NOT_CHECKED", schema_status="NOT_CHECKED"
            )
            
        genesis = records[0]
        if genesis.get("_type") != "genesis":
            return VerificationResult(
                valid=False, records_checked=0,
                failure_type="MISSING_GENESIS",
                signature_status="NOT_CHECKED", schema_status="NOT_CHECKED"
            )
            
        g_data = genesis["data"]
        # Verify genesis hash
        # Genesis hash is the hash of its own canonical payload sans genesis_hash
        g_copy = g_data.copy()
        g_copy.pop("genesis_hash", None)
        expected_g_hash = self.hasher.hash(CanonicalSerializer.serialize(g_copy))
        if expected_g_hash != g_data.get("genesis_hash"):
            return VerificationResult(
                valid=False, records_checked=1,
                first_failure_sequence=0,
                failure_type="GENESIS_HASH_MISMATCH",
                signature_status="NOT_CHECKED", schema_status="NOT_CHECKED"
            )
            
        expected_previous = expected_g_hash
        expected_seq = 1
        
        for i in range(1, len(records)):
            rec = records[i]
            if rec.get("_type") != "evidence":
                return VerificationResult(
                    valid=False, records_checked=i+1,
                    first_failure_sequence=expected_seq,
                    failure_type="INVALID_RECORD_TYPE",
                    signature_status="NOT_CHECKED", schema_status="NOT_CHECKED"
                )
                
            data = rec["data"]
            event_id = data.get("event_id")
            
            # 1. Sequence check
            if data.get("sequence_number") != expected_seq:
                return VerificationResult(
                    valid=False, records_checked=i+1,
                    first_failure_sequence=data.get("sequence_number"),
                    failure_event_id=event_id,
                    failure_type="SEQUENCE_MISMATCH",
                    signature_status="NOT_CHECKED", schema_status="PASS"
                )
                
            # 2. Previous hash check
            if data.get("previous_hash") != expected_previous:
                return VerificationResult(
                    valid=False, records_checked=i+1,
                    first_failure_sequence=expected_seq,
                    failure_event_id=event_id,
                    failure_type="CHAIN_BREAK",
                    signature_status="NOT_CHECKED", schema_status="PASS"
                )
                
            # 3. Payload hash check
            # For the payload hash, we need to reconstruct the CanonicalEvidencePayload
            payload_dict = {
                "schema_version": "1.0",
                "event_id": data.get("event_id"),
                "event_type": data.get("event_type"),
                "timestamp_ns": data.get("timestamp_ns"),
                "agent_id": data.get("agent_id", "system"),
                "session_id": data.get("session_id", "system"),
                "trace_id": data.get("trace_id", "system"),
                "source_layer": data.get("source_layer"),
                "payload": data.get("payload", {}),
                "policy_version": data.get("policy_version"),
                "model_version": data.get("model_version"),
                "configuration_hash": data.get("configuration_hash"),
                "simulation": data.get("simulation", False),
                "parent_event_id": data.get("parent_event_id"),
                "related_event_ids": data.get("related_event_ids", []),
                "telemetry_source": data.get("telemetry_source", "SIMULATION")
            }
            
            # Re-canonicalize the inner payload specifically
            canonical_bytes = CanonicalSerializer.serialize(payload_dict)
            expected_payload_hash = self.hasher.hash(canonical_bytes)
            
            if expected_payload_hash != data.get("canonical_payload_hash"):
                return VerificationResult(
                    valid=False, records_checked=i+1,
                    first_failure_sequence=expected_seq,
                    failure_event_id=event_id,
                    failure_type="PAYLOAD_HASH_MISMATCH",
                    signature_status="NOT_CHECKED", schema_status="PASS"
                )
                
            # 4. Event hash check
            chain_input = f"{expected_payload_hash}|{expected_previous}|{expected_seq}".encode('utf-8')
            expected_event_hash = self.hasher.hash(chain_input)
            
            if expected_event_hash != data.get("event_hash"):
                return VerificationResult(
                    valid=False, records_checked=i+1,
                    first_failure_sequence=expected_seq,
                    failure_event_id=event_id,
                    failure_type="EVENT_HASH_MISMATCH",
                    signature_status="NOT_CHECKED", schema_status="PASS"
                )
                
            # 5. Signature check
            sig = data.get("signature")
            if verify_signatures and not sig:
                return VerificationResult(
                    valid=False, records_checked=i+1,
                    first_failure_sequence=expected_seq,
                    failure_event_id=event_id,
                    failure_type="SIGNATURE_MISSING",
                    signature_status="FAIL", schema_status="PASS"
                )
            if verify_signatures and sig:
                # Signer verifies event_hash
                if self.signer is None or not self.signer.verify(expected_event_hash.encode('utf-8'), sig):
                    return VerificationResult(
                        valid=False, records_checked=i+1,
                        first_failure_sequence=expected_seq,
                        failure_event_id=event_id,
                        failure_type="SIGNATURE_INVALID",
                        signature_status="FAIL", schema_status="PASS"
                    )
            
            expected_previous = expected_event_hash
            expected_seq += 1
            
        return VerificationResult(
            valid=True,
            records_checked=len(records),
            head_hash=expected_previous,
            signature_status="PASS" if verify_signatures else "NOT_CHECKED",
            schema_status="PASS"
        )
