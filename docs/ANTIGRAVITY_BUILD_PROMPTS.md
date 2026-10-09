# Antigravity build prompts for AgentSentinel

Paste **one numbered prompt at a time** into Antigravity, in the same project workspace. Wait for its tests and completion report before pasting the next one. If you switch chats, the next prompt must read `docs/build-handoff.md`. These are chat prompts, not an Antigravity workflow file.

**Repository:** `https://github.com/Vansh-Anand/AgentSentinel.git`<br>
**Preferred local checkout:** `C:\Users\VANSH ANAND\Desktop\AcademIQ`<br>
**Product direction:** A real task-scoped security gateway for AI coding agents, with EffectSeal as the differentiating feature.<br>
**Existing source of truth:** `docs/AGENTSENTINEL_RESUME_READY_PLAN.md`, `docs/effectseal-design.md`, `README.md`, and the current code. These files may be uncommitted in the local checkout and absent from a fresh GitHub clone. Preserve them.

## Technical choices for the complete application

- **Backend:** Python 3.11+ (test 3.11 and 3.13), FastAPI, Pydantic v2, Uvicorn, SQLite for development evidence, `cryptography` for stable Ed25519 signing, pytest and HTTPX for tests. Use a `pyproject.toml` and lock or pin direct dependencies. Preserve compatible existing code where possible.
- **Agent:** Existing Gemini integration first, migrated from legacy `google.generativeai` to the current `google-genai` SDK after checking current Google documentation. Use explicit/manual function-call dispatch so every tool call passes through AgentSentinel. Keep a deterministic mock provider for offline tests. Never give the model a raw host-execution function.
- **Frontend:** Existing React 19, TypeScript, Vite, Tailwind, Vitest frontend. Keep the existing design where useful; display actual runtime status and evidence rather than fabricated layer scores.
- **Isolation:** Docker/Linux container for side-effecting tools; per-run workspace, default-deny egress, resource limits, dropped capabilities, no Docker socket or host secrets. Native eBPF requires a separately documented supported Linux host; Windows runs the UI/backend and deterministic simulations but cannot claim native eBPF.
- **Linux telemetry:** Existing C eBPF work, Clang/LLVM, libbpf CO-RE, bpftool/BTF, cgroups v2. Use kernel-supported tracing and health counters. The collector runs on the host, outside the agent sandbox.
- **Validation/release:** pytest, Vitest, GitHub Actions, versioned adversarial corpus, Docker Compose for local demo, synthetic secrets and a local capture endpoint. Never use real credentials or uncontrolled external exfiltration destinations in tests.

These are starting choices. If a current official SDK or repository constraint makes one incompatible, document the evidence, change the smallest necessary part, and update the handoff. Do not invent successful tests, native support, or novelty claims.

## Prompt 1 — Reconcile the repository and establish a buildable baseline

```text
Continue the AgentSentinel project in this existing repository. Read the technical choices at the top of docs/ANTIGRAVITY_BUILD_PROMPTS.md, then README.md, docs/AGENTSENTINEL_RESUME_READY_PLAN.md, docs/effectseal-design.md, docs/threat-model.md, docs/l3-native-gap-analysis.md, and any AGENTS.md/GEMINI.md instructions. Inspect git status and recent commits before editing. There are pre-existing uncommitted changes: preserve every unrelated edit and untracked result. Do not reset, clean, delete, or overwrite them. If the new agent_runtime/, README, plan, or EffectSeal design is missing because this is a fresh clone, state that in the handoff and reconstruct only the minimum required from the plan before proceeding.

Implement repository foundation, not just a report: add a Python pyproject.toml with reproducible backend/test dependencies; keep the React lockfile and scripts working; repair the incorrect clone/install instructions in deployments/linux-validation/README.md; make .gitignore correctly exclude runtime databases, caches, virtual environments, and node_modules without removing intentional benchmark fixtures. Add a single platform/capability matrix that labels each L1-L7 component REAL_RUNTIME, SIMULATED, SYNTHETIC, BENCHMARK, or UNAVAILABLE based on actual code. Keep the public README concise and accurate. Preserve AcademIQ historical documents while using AgentSentinel as the product name.

Run the gateway unittest suite, available backend tests, frontend tests/build, and a clean-install smoke test where the environment permits. Record exact commands and results. Create docs/build-handoff.md with: starting git state, files changed, tests passed/failed/skipped, remaining risks, current capability matrix, and the next prompt's prerequisites. Do not claim a phase complete if its acceptance checks did not pass.
```

## Prompt 2 — Finish the typed, default-deny tool gateway

```text
Continue from Prompt 1. Read docs/build-handoff.md, the plan, and current agent_runtime code before editing. Preserve all unrelated local work. Implement a provider-neutral, typed pre-execution gateway as the sole route from an AI agent's proposed tool call to any side-effecting tool. Use strict Pydantic v2 request/response schemas for run_id, request_id, task_id, agent identity, tool name, validated arguments, policy version/hash, decision, and execution outcome. Reject unknown tools, extra fields, malformed types, path traversal, unsupported encodings, and policy-load failures. Snapshot/normalize the exact arguments that will execute; do not evaluate one value and execute a mutable replacement. Define ALLOW, DENY, and REQUIRE_APPROVAL with stable reason codes.

Extend the current read-only gateway instead of duplicating it. Move per-task policy into versioned configuration. Implement durable request-id handling so a retry after process restart cannot repeat a side effect or change the request under the same ID. Record a decision durably before dispatch; if this fails, deny. Separate policy-decision latency from tool/model latency. Expose a clean executor interface but keep command and network execution disabled until Prompt 4's sandbox exists. The gateway must not accept an LLM's explanation as authorization.

Add meaningful tests for denied calls never reaching a fake executor, allowed calls reaching it once, concurrent duplicate requests, crash/restart idempotency, audit failure, symlink/path edge cases, malformed JSON, and caller mutation after validation. Keep the deterministic CLI demo. Update README, capability matrix, and docs/build-handoff.md with exact tests and limitations. Do not proceed to real host commands as a shortcut.
```

## Prompt 3 — Connect a real agent to the gateway

```text
Continue from Prompt 2 and read docs/build-handoff.md first. Integrate the existing Gemini provider with the current official Google GenAI Python SDK, consulting official API docs before coding. Replace the legacy free-form JSON parsing path with structured function declarations and explicit/manual dispatch. Disable automatic function execution if the SDK would otherwise invoke tools outside AgentSentinel. Keep provider/model selection configurable and report the exact model used; do not hardcode a possibly deprecated model. Support a deterministic mock provider with identical tool-call schemas for offline tests.

Build a bounded agent loop: user task -> model proposes tool call -> strict gateway validation/decision -> executor result or denial -> result returned to the model -> final answer. Limit turns, calls, output size, and time. Carry run_id/request_id/trace_id through every step. A denial should allow the model to continue safely, but it must not silently retry under a different tool to bypass the policy. The first real workflow is summarizing an authentication module from allowlisted repository files. Tool names are read_file, run_command, and http_post; run_command and http_post remain denied until Prompt 4.

Wire this loop into a new explicit live API path; keep the old simulated scenario endpoint separate and labeled. Do not fabricate L3-L7 outcomes from the tool name. Make missing GEMINI_API_KEY produce a clear unavailable or explicit mock mode, not a silent fallback presented as real. Test the full loop with a scripted fake model that proposes an allowed read, a secret read, and an external transfer. If a real Gemini key is available, run a smoke test and record its result; otherwise mark it unverified. Update frontend/API contracts as needed, README, capability matrix, and docs/build-handoff.md.
```

## Prompt 4 — Add the restricted executor, egress boundary, and approvals

```text
Continue from Prompt 3 using docs/build-handoff.md. Implement a per-run Linux container executor for all side-effecting tools. Do not run model-proposed shell commands on the host. Use a minimal image, non-root user, read-only root filesystem, explicit workspace mounts, tmpfs for scratch, no-new-privileges, dropped capabilities, process/time/memory/CPU limits, and no Docker socket or real host credentials. Network is disabled by default. If an allowlisted HTTP workflow is required, mediate it through a narrow egress component that rechecks destination, DNS result, redirects, method, data size, and policy; use a local capture endpoint in tests. Prefer structured argv execution to a shell string. Keep unknown or ambiguous shell constructs denied.

Implement run_command and http_post only through this executor. Bind each dispatch to the gateway's checked request ID and policy hash. Add REQUIRE_APPROVAL with a durable pending state, exact action/arguments/destination display, expiration, approve/deny identity, one-time resumption, and default deny on timeout. No approval is inferred from model text or repository content. If Docker/Linux is unavailable, report the live executor as UNAVAILABLE; never fall back to host execution.

Demonstrate an allowed safe command, a blocked destructive command, a denied secret read, a denied outbound transfer with zero bytes at the capture endpoint, and an approved action that executes once. Test timeouts, process-tree cleanup, retries, redirects, and policy failures. Update Docker Compose or equivalent local demo setup, docs, status UI/API, and docs/build-handoff.md. Explain platform limits honestly.
```

## Prompt 5 — Make L2 semantic defense real at the execution boundary

```text
Continue from Prompt 4. Read the handoff and inspect existing l2_sdn parser, normalizers, canonicalizer, policy matcher, TOCTOU code, and adversarial tests. Route run_command proposals through these components before the container executor. Produce a canonical command/argv and a deterministic policy verdict; the executor must run precisely the checked representation. Preserve the raw input and canonical digest for evidence, but never evaluate untrusted shell substitutions during normalization. Deny ambiguous or unsupported syntax. Ensure compound commands, pipelines, encoded payloads, quotes, aliases, path tricks, and Windows/Linux path differences have explicit outcomes.

Fix the current validate-then-reopen gap for file reads where feasible using descriptor-relative operations on Linux and sandbox mount boundaries. Do not claim race freedom based solely on two path-stat checks. Ensure all command execution remains in the restricted container. Keep L1 generation-time constraints separate from this post-proposal tool gate.

Expand adversarial tests with benign controls: every blocked command must have zero executor calls; allowed commands must execute exactly once; obfuscated malicious commands must not become allowed merely because normalization fails. Measure real L2 policy latency over a versioned corpus rather than reporting earlier synthetic timings as live. Update the capability matrix and handoff. If a parser class cannot safely support a syntax form, document and deny it rather than guessing.
```

## Prompt 6 — Integrate verifiable L6 evidence

```text
Continue from Prompt 5 and read docs/build-handoff.md plus existing l6_eces modules. Make one evidence pipeline for the real agent runtime: proposed call, normalized call, policy decision, approval, executor start/result, and error must share run_id/request_id/trace_id. Integrate the gateway's simple JSONL log into L6 or replace it with one transactional source of truth. Redact secrets before persistence; store sensitive arguments/output as narrowly scoped digests or references. Never log a synthetic secret value in plaintext.

Use stable, safely stored software signing identity across restarts and export a public verification key. Correct any algorithm metadata that disagrees with the actual signing curve. Preserve existing evidence compatibility or write a documented migration. Anchor chain heads outside the writable SQLite store in a way that makes tail truncation detectable under the stated trust model. Keep the signing key outside the tool container. Provide an offline verifier and an API to export/verify a session.

Test normal verification; restart recovery; record edit, insertion, reorder, deletion, and tail truncation; wrong key; audit write failure; and concurrent appends. A failure to record a pre-execution decision must deny dispatch. Show evidence status in the dashboard without claiming hardware attestation. Update documentation, capability matrix, and handoff with the exact trust assumptions and tests.
```

## Prompt 7 — Implement EffectSeal's deterministic core

```text
Continue from Prompt 6. Read docs/effectseal-design.md and docs/build-handoff.md. Implement the novel project feature's deterministic core before any native telemetry dependency. The gateway must derive a typed effect envelope from trusted task policy and the tool contract, never from a model-written rationale. Include allowed executable/argv, file scopes, network destinations, time/resource limits, request ID, sandbox identity, and policy hash as applicable. Create a canonical digest of that envelope.

Create typed observation events and a pure reconciler that compares observations and executor outcomes against the envelope. Results are MATCH, VIOLATION, INCOMPLETE, and NOT_EXECUTED. An unknown process, extra child, unauthorized file/network attempt, failed correlation, dropped required event, or collector outage must never produce MATCH. Distinguish an attempted operation from a completed effect by return status. Add a signed EffectSeal receipt to L6 with hashes of authorization, normalized observations, executor result, status, reason codes, and telemetry coverage. Avoid signing only an in-memory object that cannot be independently reconstructed.

Build deterministic fixtures for: benign summary; approved command spawning an unexpected child; attempted .env read; attempted outbound connection; command arguments changed after authorization; missing/duplicate/reordered observations; unrelated cgroup events; and complete collector outage. Verify each receipt offline and show a compact CLI explanation. No claims of native eBPF yet. Record tests and limitations in the handoff; update the plan and README with actual status.
```

## Prompt 8 — Connect native Linux L3 telemetry to EffectSeal

```text
Continue from Prompt 7. Read docs/build-handoff.md, docs/l3-native-gap-analysis.md, l3_ebpf/, and the EffectSeal contract. On a supported native Linux host, finish the existing eBPF loader/collector path using Clang/LLVM, libbpf CO-RE, bpftool/BTF, and cgroups v2. Start with execve and connect enter/exit events; add openat/openat2 file observations only when path identity and return outcomes can be reconciled reliably. Keep the collector outside the untrusted tool container. Map each event to sandbox/cgroup, process ancestry, and request ID. Track event drops, ring-buffer overflow, attach failure, collector restarts, and time synchronization quality.

Feed real observations into EffectSeal. Demonstrate: a benign approved command produces MATCH; a compromised test script performs an extra exec/network attempt and produces VIOLATION; a stopped collector produces INCOMPLETE. Keep the sandbox as the preventive boundary; do not describe eBPF tracepoints as stopping an already executing syscall. Add a native-Linux test profile and a separate deterministic replay profile for Windows/CI. If the current host cannot attach native probes, implement and test what is possible, mark native validation unverified, and give exact Ubuntu commands and expected output for the remaining gate. Do not convert replay results into a native PASS. Update health/status API, docs, and handoff.
```

## Prompt 9 — Wire L5 governance and evaluate L4 honestly

```text
Continue from Prompt 8. Read the handoff and existing l4_divergence/ and l5_riskchain/ code. Wire real runtime events, gateway denials, and EffectSeal mismatches into L5 session state using stable run/request identities. Define hard-rule precedence: a deterministic policy DENY remains denied regardless of any ML score. A real multi-step sequence such as protected-file access followed by egress attempt must update risk and cause a concrete action: pause subsequent tool dispatch, require review, or freeze only the correct sandbox/cgroup. Show the action's actual success/failure, never an invented dashboard layer. Add recovery/resume rules with authenticated authorization and tests for cross-session isolation.

For L4, create a dataset/evaluation manifest separating real traces, replayed traces, and synthetic fixtures. Use existing Isolation Forest/PyTorch components only if trained and evaluated on independent held-out real data with calibrated thresholds, false-positive results, drift checks, and model versioning. If this evidence is unavailable, leave L4 as SYNTHETIC/BENCHMARK and do not let it drive live enforcement. Test benign repeated commands, a malicious multi-step attempt, noisy telemetry, missing telemetry, and an L5 freeze/pause followed by authorized resume. Update the capability matrix, dashboard data contract, and handoff with measured values and exclusions.
```

## Prompt 10 — Validate L1 and L7 without overstating support

```text
Continue from Prompt 9. Read the handoff, existing l1_gcd/ and l7_trust/ code, and the live agent adapter. For L1, validate the existing Hugging Face generation-time logits adapter against a real supported local model and current policy. Demonstrate that disallowed tool-call continuations cannot be sampled, measure generation overhead, and test no-legal-token failure. Keep this explicitly model-specific. Gemini function-call validation at the gateway is post-proposal enforcement, not pre-softmax decoding; do not label it generation-time GCD. If the local model cannot run on available hardware, keep the adapter tested with fixtures and mark real-model validation unavailable.

For L7, implement a clean trust-provider interface and truthful health reporting. On hosts without a real supported TPM/TEE attestation path, return UNAVAILABLE with a clear reason and do not issue a simulated success receipt. If supported hardware is available, verify nonce freshness, measurement allowlist, signature/certificate chain, and isolation boundary using actual hardware evidence; otherwise preserve simulation only as a separate test mode. Add tests for forged/stale measurements and status transitions. Ensure neither L1 nor L7 silently blocks the already working L2/L6/EffectSeal demo when their hardware/model prerequisites are absent. Update docs, capability matrix, and handoff.
```

## Prompt 11 — Finish the live API and recruiter-friendly frontend

```text
Continue from Prompt 10. Read docs/build-handoff.md, the frontend/backend API contract, existing FastAPI routers/services, and React pages. Make the application a coherent end-to-end product with one source of truth for live runs. API routes should create a run, stream or poll its state, list the proposed and executed tool calls, return policy decisions and approval requests, show EffectSeal status, export/verify evidence, and expose truthful layer/collector health. Validate requests and constrain response sizes. Protect mutating/review endpoints for local-demo use; document any deployment authentication requirement. Keep simulated historical scenario routes separate.

In the existing React/TypeScript/Vite frontend, create a clean flow: start a legitimate task, inspect the agent's proposed action, see ALLOW/DENY/REQUIRE_APPROVAL with reason, view actual execution outcome, compare approved vs observed effects, and verify evidence. Show MATCH/VIOLATION/INCOMPLETE/NOT_EXECUTED clearly. Show REAL_RUNTIME, SIMULATED, SYNTHETIC, BENCHMARK, and UNAVAILABLE consistently. Remove hardcoded L3/L4/L5 scores and heuristic stopping layers from live views; retain historical benchmark pages with explicit labels. Support empty/error/loading states and accessibility. Add API contract tests, component tests, and at least one browser-level demo-path test if tooling is available. Run frontend build/lint/tests and backend tests. Update handoff and screenshots only after visual inspection.
```

## Prompt 12 — Build the security evaluation and CI gates

```text
Continue from Prompt 11. Read docs/build-handoff.md and prior benchmark reports. Build a versioned adversarial evaluation corpus with at least 100 malicious and 100 benign cases, starting from existing fixtures but adding held-out cases. Include malicious README/code comments, tool-result injection, authority spoofing, obfuscated/compound commands, path traversal/symlink swaps, multi-step exfiltration, compromised-tool hidden side effects, and benign mentions of security terms. Use only synthetic secrets and a local capture endpoint. Record expected authorized behavior and attack objective separately for each case.

Run comparable configurations: unguarded baseline in a disposable sandbox, gateway only, gateway+sandbox, and full validated EffectSeal configuration. Measure actual file/network side effects, attack success rate, denied calls executed, legitimate task completion, false-block rate, p50/p95 decision and end-to-end latency, telemetry correlation accuracy/loss, and evidence verification. Clearly distinguish deterministic scripted-agent results from stochastic real-model runs; repeat real-model trials, pin model/version/settings, and publish numerator/denominator. Add layer-ablation results showing each live layer's marginal benefit and cost. No synthetic L4/L5 score should be called a live detection result.

Add GitHub Actions for Python tests/type/lint, frontend tests/build, deterministic attack corpus, dependency scanning, and secret scanning where feasible. Native eBPF tests should have a separate Linux job/profile with clear runner capability requirements, not a falsely green skipped test. Produce machine-readable JSON/CSV and a human-readable report generated from the same source. Fix failures and update the handoff with exact commands, results, and unverified gates.
```

## Prompt 13 — Package, verify, and present the complete application

```text
Continue from Prompt 12. Read docs/build-handoff.md and the plan's definition of resume-ready. Complete the release package: one documented local launch path using Docker Compose (or a documented equivalent), a fixture repository with a malicious README and synthetic secret, a local capture endpoint, API/backend, and frontend. A fresh reviewer must be able to run a benign task, trigger the injected attempt, observe the blocked/contained action, view the EffectSeal receipt, and verify the evidence offline. Provide a separate supported-Ubuntu procedure for native eBPF. If native tracing or hardware attestation remains unavailable, label it explicitly and keep the rest of the app usable.

Polish README with a 30-second problem statement, architecture diagram, exact stack, quickstart, screenshots, a 90-120 second demo script/video storyboard, threat model, limitations, capability matrix, and links to reproducible evaluation data. Add SECURITY.md and contributor/testing instructions. Review the repository for tracked secrets, runtime databases, caches, oversized artifacts, stale placeholder URLs, broken imports, and misleading claims. Verify from a clean checkout or isolated copy, not only the developer's current environment. Run the full deterministic suite, frontend suite/build, API smoke test, attack demo, evidence verifier, and available native Linux validation. Do not invent success for unavailable hardware, missing credentials, or a failed test.

Produce a final release report with changed files, exact commit/version tested, installation steps, measured security and utility results, remaining risks, and a resume bullet containing only measured numbers. Keep publication/push/deployment as a separate explicit action if credentials or external state changes are required. Update docs/build-handoff.md one last time and state which of the seven layers are truly live.
```

## How to use the sequence

If a prompt finishes with a failed acceptance gate, give Antigravity the **same prompt again**, plus its own failure report, and ask it to repair that milestone before moving on. Do not advance because a page looks polished or because tests were skipped. The final resume claim should come from Prompt 12's measured results and Prompt 13's clean-checkout verification.

### Current documentation references

- [Google GenAI SDK migration](https://ai.google.dev/gemini-api/docs/migrate) and [coding-agent guidance](https://ai.google.dev/gemini-api/docs/coding-agents)
- [FastAPI testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [Docker Compose service controls](https://docs.docker.com/reference/compose-file/services/)
- [Linux libbpf CO-RE overview](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html)
