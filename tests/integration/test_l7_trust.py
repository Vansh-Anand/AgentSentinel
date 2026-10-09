import pytest
import time
from l7_trust.detector import ConfidentialComputingDetector
from l7_trust.tee.provider import SimulationTEEProvider
from l7_trust.attestation.verifier import AttestationVerifier
from l7_trust.measurement.manifest import SecurityArtifactManifest, MeasurementGenerator
from l7_trust.domain.isolation import AgentDomain, SecurityDomain, IsolationVerifier

def test_hardware_detector():
    caps = ConfidentialComputingDetector.detect()
    # On Windows, we expect everything hardware-related to be False/SIMULATED
    assert caps.os_name in ["Windows", "Linux"]
    if caps.os_name == "Windows":
        assert caps.tdx_available is False
        assert caps.sev_snp_available is False

def test_simulation_attestation_flow():
    manifest = SecurityArtifactManifest(
        l1_policy_hash="l1_hash",
        l2_policy_hash="l2_hash",
        l3_bpf_hash="l3_hash",
        l4_model_hash="l4_hash",
        l5_governance_hash="l5_hash",
        configuration_hash="config_hash"
    )
    
    # Generate trusted measurement
    expected_measurement = MeasurementGenerator.generate_manifest_hash(manifest)
    
    provider = SimulationTEEProvider(expected_measurement)
    verifier = AttestationVerifier(expected_measurement=expected_measurement)
    
    # 1. Challenge
    challenge = verifier.create_challenge()
    
    # 2. Quote
    evidence = provider.get_attestation(nonce=challenge.nonce)
    
    # 3. Verify
    result = verifier.verify(evidence, challenge.nonce)
    assert result.valid is False
    assert result.hardware_attested is False
    assert result.simulation_valid is True
    assert result.measurement_match is True
    assert result.signature_valid is False

def test_attestation_expired_challenge():
    manifest = SecurityArtifactManifest(
        l1_policy_hash="h", l2_policy_hash="h", l3_bpf_hash="h",
        l4_model_hash="h", l5_governance_hash="h", configuration_hash="h"
    )
    expected_measurement = MeasurementGenerator.generate_manifest_hash(manifest)
    
    provider = SimulationTEEProvider(expected_measurement)
    verifier = AttestationVerifier(expected_measurement=expected_measurement, max_age_seconds=-1) # Immediate expiry
    
    challenge = verifier.create_challenge()
    evidence = provider.get_attestation(nonce=challenge.nonce)
    
    result = verifier.verify(evidence, challenge.nonce)
    assert result.valid is False
    assert result.fresh is False
    assert "expired" in result.failure_reason.lower()

def test_attestation_wrong_measurement():
    manifest = SecurityArtifactManifest(
        l1_policy_hash="h", l2_policy_hash="h", l3_bpf_hash="h",
        l4_model_hash="h", l5_governance_hash="h", configuration_hash="h"
    )
    expected_measurement = MeasurementGenerator.generate_manifest_hash(manifest)
    
    # Provider generates quote with TAMPERED measurement
    provider = SimulationTEEProvider("TAMPERED_HASH")
    verifier = AttestationVerifier(expected_measurement=expected_measurement)
    
    challenge = verifier.create_challenge()
    evidence = provider.get_attestation(nonce=challenge.nonce)
    
    result = verifier.verify(evidence, challenge.nonce)
    assert result.valid is False
    assert result.measurement_match is False


def test_forged_simulation_quote_is_rejected():
    verifier = AttestationVerifier(expected_measurement="known")
    challenge = verifier.create_challenge()
    evidence = SimulationTEEProvider("known").get_attestation(challenge.nonce)
    result = verifier.verify(evidence.model_copy(update={"quote_reference": "forged"}), challenge.nonce)
    assert result.valid is False
    assert result.simulation_valid is False


def test_stale_evidence_and_replayed_nonce_are_rejected():
    verifier = AttestationVerifier(expected_measurement="known")
    challenge = verifier.create_challenge()
    evidence = SimulationTEEProvider("known").get_attestation(challenge.nonce)
    stale = verifier.verify(evidence.model_copy(update={"timestamp": challenge.issued_at - 60}),
                            challenge.nonce)
    assert stale.fresh is False
    assert verifier.verify(evidence, challenge.nonce).fresh is False


def test_unverified_native_quote_never_claims_hardware_attestation():
    verifier = AttestationVerifier(expected_measurement="known")
    challenge = verifier.create_challenge()
    evidence = SimulationTEEProvider("known").get_attestation(challenge.nonce)
    claimed_native = evidence.model_copy(update={"attestation_type": "TDX_QUOTE", "platform": "Intel TDX"})
    result = verifier.verify(claimed_native, challenge.nonce)
    assert result.valid is False
    assert result.hardware_attested is False
    assert result.signature_valid is False

def test_domain_isolation():
    agent = AgentDomain(agent_id="test_agent", namespace_ids=["ns1"], policy_id="pol1", cgroup_id=None, root_pid=None)
    security = SecurityDomain(domain_id="sec_dom", components=["L1"], attestation_state="VALID", integrity_state="VALID", policy_state="VALID")
    
    assert IsolationVerifier.verify_boundary(agent, security) is True
    
    # If agent elevates to T2, boundary is violated
    agent_elevated = AgentDomain(agent_id="test_agent", namespace_ids=["ns1"], policy_id="pol1", trust_level="T2", cgroup_id=None, root_pid=None)
    assert IsolationVerifier.verify_boundary(agent_elevated, security) is False
