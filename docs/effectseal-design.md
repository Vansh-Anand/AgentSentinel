# EffectSeal: Verify What an Agent Tool Actually Did

**Status:** Deterministic reconciler, restricted container fixture, and Ed25519-signed run evidence are implemented. Three native entry probes compile and the observation bridge has contract tests. Request-specific native attachment, complete syscall coverage, and an independently anchored receipt remain unvalidated.<br>
**Role in AgentSentinel:** Connect the existing seven-layer research architecture to one testable security question.

## The question

A gateway can approve an agent's `run_command("python scripts/summary.py")` request, but that approval says little about what the script and its child processes actually do. A compromised tool can read another file, spawn a shell, or attempt a network connection while returning an innocent-looking result.

**EffectSeal asks:** Did the tool's *observed effects* stay inside the *effect envelope* authorized for this specific task and request?

This is a proposed engineering contribution, not a claim that execution receipts or intent-to-OS correlation were invented here. Related work includes [AgentSight](https://arxiv.org/abs/2508.02736), which correlates agent-level intent with system events, and [IntAct](https://arxiv.org/abs/2610.04375), which studies whether tool calls are transformed across execution hops. AgentSentinel's target is a reproducible security control and evidence workflow that compares an explicit task policy, sandbox outcome, and observed process effects for the same call.

## Core mechanism

For each approved tool call, the gateway creates an **effect envelope** from trusted policy and the tool contract. The model's explanation is never authority. The envelope can specify:

- executable and argument constraints;
- readable/writable workspace paths or mount scopes;
- permitted network destinations and methods;
- process, byte, and time limits;
- run ID, request ID, sandbox/cgroup identity, and policy hash.

The executor applies the envelope through sandbox controls. A Linux collector observes relevant process, file, and network attempts and outcomes for that sandbox. A reconciler compares the normalized observations with the envelope and emits one of four results:

| Result | Meaning |
| --- | --- |
| `MATCH` | Captured effects stayed within the authorized envelope and required telemetry was complete. |
| `VIOLATION` | At least one observed attempt or completed effect exceeded the envelope. |
| `INCOMPLETE` | Telemetry loss, correlation ambiguity, collector outage, or missing outcome prevents a confident match. |
| `NOT_EXECUTED` | The gateway denied the call before invoking the executor. |

`INCOMPLETE` must never be shown as safe. Detection after a syscall is not prevention of that syscall. Gateway policy and sandbox restrictions provide the preventive boundary; EffectSeal detects disagreement, explains it, and can stop **subsequent** calls or quarantine the run.

## Event and receipt contract

```text
Authorization:
  run_id, request_id, task_id, normalized_tool_call_hash,
  policy_hash, effect_envelope_hash, sandbox_id, issued_at

Observation:
  request_id, sandbox_id, process_tree_id, event_kind,
  normalized_target, attempted_or_completed, return_status,
  timestamp, collector_health

EffectSeal receipt:
  authorization_hash, observation_set_hash, result,
  mismatch_reason_codes, collector_coverage, executor_result_hash,
  evidence_chain_sequence, signer_key_id, signature
```

Store sensitive arguments and tool output only as redacted values or digests. Keep the signing key outside the agent/tool sandbox. Bind a receipt to a stable public key and an externally anchored chain head, following the L6 evidence work in the main plan.

## How it uses the seven layers

1. **L1:** Optionally constrains the model's tool-call shape for supported models; its output is still checked by the gateway.
2. **L2:** Normalizes and checks the proposed call before execution, then produces the effect envelope.
3. **L3:** Supplies native Linux observations tied to the executor's cgroup/process tree. Include syscall outcomes where possible; an enter event alone is only an attempt.
4. **L4:** May flag unusual sequences as an additional signal, without overriding hard policy or making a `MATCH` claim when telemetry is incomplete.
5. **L5:** Correlates mismatches across calls and can freeze future activity in that sandbox.
6. **L6:** Signs the authorization, observations, and reconciliation result into verifiable evidence.
7. **L7:** Can later attest the collector/executor host if real TPM/TEE support is available; it is not necessary for the first EffectSeal release.

## Minimum demonstration

**Benign:** The agent asks to summarize a repository. The gateway permits `python scripts/summary.py` in a disposable Linux sandbox. The script reads only approved files and makes no network request. Receipt: `MATCH`.

**Compromised tool:** The same approved command is replaced with a test script that also attempts to read a synthetic `.env` and contact a local capture endpoint. Sandbox restrictions prevent unauthorized access/egress. L3 observes the relevant failed attempts and process ancestry. Receipt: `VIOLATION`, with the exact policy rule and observed attempted effect. The capture endpoint receives no secret.

**Telemetry outage:** Repeat with the collector deliberately stopped or an event dropped. Receipt: `INCOMPLETE`; the UI states what cannot be verified. The sandbox still enforces its restrictions.

All secrets and endpoints are local test fixtures. Avoid real credentials or external destinations.

## Implementation sequence

1. **Deterministic prototype (complete for fixtures):** Typed envelopes, correlated observations, and `MATCH`/`VIOLATION`/`INCOMPLETE`/`NOT_EXECUTED` verdicts are in `agent_runtime/effectseal.py`. Tests cover allowed reads, unauthorized network and child-process attempts, denied calls, correlation mismatch, reordered events, execution failure, and dropped telemetry. No native-security claim at this stage.
2. **Sandbox integration:** Bind the approved request to one sandbox process tree. Apply filesystem and network restrictions independently of the collector.
3. **Native Linux collector (partial):** `execve`, `openat`, and IPv4/IPv6 `connect` entry probes compile. The cgroup filter and drop counter are bridged to Python. The mapper handles absolute workspace paths and flags relative or unresolved paths; it cannot claim `MATCH` from this partial coverage. Exit outcomes, `openat2`, child-process completeness, and unique request cgroups remain to be validated on Linux.
4. **Evidence integration:** Record authorization and observations in L6 and sign the receipt with stable key identity. Verify exports offline across restarts and tampering.
5. **Dashboard:** Show `approved effect → observed attempt/outcome → containment → receipt status`. Keep simulated and native receipts visually distinct.
6. **Evaluation:** Compare gateway-only, gateway+sandbox, and gateway+sandbox+EffectSeal. Measure prevention separately from detection and explanation quality.

## Acceptance criteria

- A denied call has no executor invocation and produces `NOT_EXECUTED`.
- A permitted benign call produces `MATCH` only with complete, correctly correlated telemetry.
- An unexpected child process or network/file attempt produces `VIOLATION`, even when the final tool response says “success.”
- Any dropped/uncorrelated required event produces `INCOMPLETE`, not `MATCH`.
- The compromised-tool fixture causes zero secret delivery at the capture endpoint.
- Offline verification detects a modified authorization, observation, or receipt.
- Results report true/false mismatch rates, correlation accuracy, telemetry loss, legitimate-task completion, and p50/p95 runtime overhead on a named Linux environment.

## Why this stands out on a resume

Most portfolio demos stop at “the policy blocked a bad tool call.” EffectSeal can show a more demanding engineering story: **the approved call was executed in a constrained environment, its actual process effects were checked against the permission it received, and the outcome was independently verifiable.** That connects application security, Linux observability, experimental evaluation, and cryptographic evidence in one understandable case. Its strength must come from the measured implementation, not the feature name.
