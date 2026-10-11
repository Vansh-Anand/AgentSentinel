from dashboard_api.services.challenge_service import ChallengeRequest, run_challenge


def run(layer: str, payload: str, action: str = "read_file"):
    return run_challenge(ChallengeRequest(layer=layer, payload=payload, action=action)).model_dump()


def test_all_seven_challenges_are_explicit_about_proof_level():
    cases = [
        ("L1", '{"tool":"sys_exec","arguments":{}}', "BLOCK", "SCHEMA_CHECK", "UNKNOWN_TOOL"),
        ("L2", ".env", "BLOCK", "LIVE_GATEWAY", "PATH_OUT_OF_SCOPE"),
        ("L3", "sys_open(/etc/shadow)", "SIMULATED_BLOCK", "SIMULATION", "SENSITIVE_KERNEL_EVENT"),
        ("L4", "read -> request_sudo -> kernel", "SIMULATED_BLOCK", "SIMULATION", "BEHAVIOR_SEQUENCE_MARKER"),
        ("L5", "login_fail -> retry -> sudo", "SIMULATED_BLOCK", "SIMULATION", "SEQUENCE_RISK_THRESHOLD"),
        ("L6", "modified audit event", "BLOCK", "LIVE_INTEGRITY_CHECK", "MAC_INVALID"),
        ("L7", "quote mismatch", "UNAVAILABLE", "UNAVAILABLE", "TPM_HOST_UNAVAILABLE"),
    ]
    for layer, payload, verdict, mode, reason in cases:
        result = run(layer, payload)
        assert (result["verdict"], result["mode"], result["reason_code"]) == (verdict, mode, reason)
        assert result["explanation"] and result["rule"]
        assert result["executed"] is False
        if layer == "L2":
            assert result["audit_valid"] is True and result["receipt_valid"] is True


def test_custom_l2_inputs_use_actual_allowlist_and_never_run_commands():
    assert run("L2", "README.md")["verdict"] == "ALLOW"
    assert run("L2", "../secret")["reason_code"] == "INVALID_PATH"
    command = run("L2", "whoami", "execute_command")
    assert command["reason_code"] == "COMMAND_EXECUTION_DISABLED"
    assert command["executed"] is False
    assert run("L2", "https://example.invalid/ingest", "http_post")["reason_code"] == "NETWORK_EXECUTION_DISABLED"


def test_custom_replay_does_not_claim_protection_for_unmatched_text():
    for layer in ("L3", "L4", "L5"):
        result = run(layer, "ordinary read")
        assert result["verdict"] == "SIMULATED_ALLOW"
        assert result["mode"] == "SIMULATION"
