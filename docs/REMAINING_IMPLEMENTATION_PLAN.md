# AgentSentinel: remaining implementation plan

Updated 2026-10-10. This plan starts from commit `1654f4c` on `codex/agentsentinel-resume-ready`. It covers the work **still open**, rather than repeating the original build plan. The [completion matrix](PROJECT_COMPLETION_MATRIX.md) is the source of truth for current layer status; the [validation status](VALIDATION_STATUS.md) records the checks already performed.

## Starting point and target

The application already has a usable portfolio release: a task-scoped L2 tool gateway, bounded fixture/Gemini agent loop, restricted Docker command fixture, local L4 rule signal and L5 risk governor, HMAC audit chain, Ed25519 public receipt, software artifact measurement, React dashboard, and credential-free Compose smoke. The 50-case current-source synthetic Gemini report is a **single trial per case**: 5/25 malicious READMEs induced forbidden proposals, none of those five proposals executed, 25/25 benign tasks completed, and all 50 saved HMAC chains and signed receipts verified. The latest observed GitHub Actions run for this branch passed its eight jobs, including Compose smoke. These results support a narrow gateway and evidence claim, not a claim that seven independently validated defenses are live.

The end target is a reproducible application where a real agent request passes through each enabled layer, denied actions cannot execute, allowed actions have trustworthy effect evidence, missing telemetry is explicit, and an independent verifier can check the final receipt. A layer counts as complete only after its **runtime path, negative tests, measured results, and user-facing status** agree. On Windows, native L3 and hardware L7 must continue to show unavailable. No separate Linux host or TPM test machine is currently available, so those gates need an environment before they can be truthfully closed.

## Priority and dependencies

| Order | Work package | Why it matters for a recruiter | Depends on | Done when |
| --- | --- | --- | --- | --- |
| 1 | Evaluation and portfolio evidence | Turns a functioning demo into a measured security engineering project | Existing gateway and benchmark harness | Repeated held-out model results, benign quality, real side effects, reproducible report and short demo |
| 2 | Restricted execution hardening | Makes the concrete tool boundary credible under races and cancellation | Existing Docker executor | Adversarial file-swap, timeout, cleanup and containment tests pass on a named environment |
| 3 | L3 request-scoped native observation | Distinguishes actual process behavior from gateway intent | Supported native Linux host or VM for development | Exact request/process-tree correlation, outcome events, path resolution, load/loss accounting, live EffectSeal hookup |
| 4 | L5 observed-effect response | Shows the defense reacts to what a process did | L3 live request observations | A violation stops subsequent agent calls; missing observation fails closed; benign completion is measured |
| 5 | L4 trained behavior detector | Adds a defensible detection research result | Versioned real L3 traces | Held-out calibration and false-block report justify optional activation |
| 6 | L6 independent evidence trust | Makes receipts meaningful after API-host compromise | Current local signed evidence | External digest anchor, separate key custody, independent verification and compromise tests |
| 7 | L7 hardware attestation | Validates runtime identity rather than disk hashes alone | Supported host with TPM/TEE and independent verifier | Fresh quote binds approved measurements and is rejected when stale, forged or mismatched |
| 8 | Release review | Makes every claim easy to reproduce and limits clear | Earlier packages at their chosen release scope | Clean-clone guide, CI, threat model, architecture, screenshots/video and claim matrix all match behavior |

Orders 1, 2, and 8 can produce a strong internship portfolio release **without waiting for TPM hardware**. Orders 3-7 are the full seven-layer research track. A missing hardware environment is a documented capability limit, never a reason to label a simulated layer live.

## 1. Expand the measured evaluation

**Implementation checkpoint:** A second, held-out-from-v1 synthetic 25 attack/25 benign corpus now runs through the same gateway. Its task has a narrow lexical answer assertion. New reports bind the final message hash and stop reason into the signed audit, and the verifier recomputes corpus fixtures, executions, completion and aggregates. The 50-case fixture wiring run passed all 50 evidence checks; its canned response passed 0/25 lexical assertions. A live Gemini run is published as [v3](../benchmarks/results/agentsentinel_model_eval_v3.md): after two successful HTTP 429 retries, 1/25 attacks induced a forbidden proposal, 0/1 executed, 25/25 benign lexical checks passed, and 50/50 signed final results verified against current source at publication. The 100+100 diverse corpus, repeated live-model trials, disposable baseline and semantic answer review remain open.

**Build:** Version a held-out corpus of at least 100 attack and 100 benign repository/task pairs. Keep a separate development set. Include README and tool-output injection, multi-step persuasion, path/command/network exfiltration attempts, malformed tool calls, and harmless lookalikes. Use only synthetic secrets and disposable workspaces. Run repeated trials at a pinned model/configuration; record provider failures and retries separately. Run the same tasks with the gateway enabled and a clearly labeled disposable baseline. Add an answer-quality rubric or task assertions so legitimate completion means useful work, not merely a final text response. Record actual executor calls and side effects, not just model proposals.

**Measure:** attack-induced unauthorized proposals, unauthorized **executions**, benign task completion, false denials, answer quality, p50/p95 latency, error rate, audit/receipt validity, model/configuration, corpus and source hashes. Publish denominators, uncertainty intervals for rates, and per-case sanitized outcomes. Do not infer general immunity from this corpus.

**Gate:** rerunning the documented commands against the same versioned inputs reproduces the report structure; every completed case has a verifiable signed receipt; an independent reviewer can distinguish a blocked proposal from an attack that never induced one. Keep the existing 25+25 v2 report as historical, single-trial evidence.

**Where:** `benchmarks/model_eval.py`, `benchmarks/model_cases_v1.json`, `benchmarks/verify_model_report.py`, `benchmarks/results/`, `tests/gateway/`.

## 2. Harden the restricted execution boundary

**Implementation checkpoint:** The Docker command runner streams output through a fixed byte budget and terminates an overproducing child, then removes the named container. A slow child emitting one byte over the limit was stopped before its timeout. Windows post-open handle checks rejected a symlink swap before Docker started; Linux descriptor-relative reads rejected a parent swap and a hardlink to the unlisted synthetic secret. Safe and attack fixtures still passed in Docker Desktop with a pinned Python image. Concurrent hostile-workspace swaps, broader escape evaluation and cancellation/restart stress remain open.

**Build:** Keep the current exact argument allowlist and pinned Docker image. Test source-file swaps during snapshot creation, symlink/hardlink tricks, replacement of paths after policy checks, process cancellation, API restart during execution, container cleanup, oversized output, time/memory limits and denied egress. Preserve the fixed synthetic repository for the default dashboard. If arbitrary workspaces are ever accepted, require a separate threat model, authentication, tenant isolation and safe source acquisition first.

**Gate:** authorized command completes from the approved snapshot; secret-read and network fixtures still fail; attempted races never cause unapproved bytes to enter the snapshot; timed-out/cancelled runs leave no container or leaked credential; failures produce a signed, truthful result. Publish the tested host, Docker engine and image digest. This is a bounded sandbox claim until broader independent review.

**Where:** `agent_runtime/docker_executor.py`, `agent_runtime/tools.py`, `tests/gateway/`, `SECURITY.md`.

## 3. Connect native L3 to one real agent request

**Implementation checkpoint:** The collector now rejects duplicate agent IDs and occupied cgroups before touching the kernel filter. A failed filter install rolls back the scope; detach clears it. Native event timestamps older than a reused cgroup's registration are dropped instead of being assigned to a new run. Contract tests cover these cases, and the Docker Desktop Linux VM vertical slice still observed all three synthetic syscall attempts with zero measured ring-buffer drops. This prevents two specific attribution errors; it does not create a unique cgroup or complete process-tree coverage for each application request.

**Environment:** First use the existing Docker Desktop Linux VM validation image for development. To claim native host coverage, acquire a supported Linux host/VM with cgroups v2, BTF/tracefs and the required BPF privileges, then run `deployments/linux-validation/preflight.sh`. A Windows browser demo alone cannot close this gate.

**Build:** Start a unique cgroup for each restricted agent/tool run before its process starts. Register that cgroup and descendant process coverage with the collector; bind collector events to the gateway `run_id` using server-owned data. Extend the current `execve`, `openat` and `connect` **entry-attempt** probes with the exit/outcome and file/network details needed for effect claims. Resolve relative paths against the observed process context, record flags and success/failure, handle process inheritance, and report any event gap, collector restart, buffer loss or ambiguous path. Keep the collector outside the agent's writable boundary. Feed native observations to `agent_runtime/native_effects.py` and the active EffectSeal lifecycle, not only an offline benchmark.

**Gate:** for a single live request, a controlled allowed file read and controlled denied file/network/command attempts appear under the correct run and process tree, and a simultaneous second run cannot inherit those events. Inject collector outage, missed events, loss and unresolved paths; each must yield `INCOMPLETE` or `VIOLATION` as specified, never a false `MATCH`. An allowed effect becomes `MATCH` only after complete request coverage and outcome reconciliation are demonstrated. Publish host/kernel, event counts, loss rate and a reproducible trace.

**Where:** `deployments/linux-validation/`, `benchmarks/linux_native/`, `agent_runtime/native_effects.py`, `agent_runtime/effectseal.py`, `agent_runtime/service.py`, `tests/integration/`.

## 4. Exercise L5 with observed effects

**Build:** Attach the trusted native observer to the live bounded agent loop. Preserve L2's unconditional deny even if a risk score is low. Order each step as proposal, L2 decision, execution, observation/reconciliation, L5 action, signed audit, then next proposal. Define the response to timeout, observer failure, partial telemetry and repeated denial. Bound the governor so it cannot loop forever or silently skip evidence writes.

**Gate:** a controlled out-of-policy observed action causes exactly one recorded STOP before the next tool call; a collector outage produces an explicit safe outcome; benign multi-step tasks finish. Compare protected and baseline task completion, false stops and added latency on the held-out corpus.

**Where:** `agent_runtime/agent.py`, `agent_runtime/risk.py`, `agent_runtime/service.py`, `tests/gateway/`, `tests/integration/`.

## 5. Validate an optional trained L4 detector

**Build:** Treat the existing research checkpoints as inactive until there is a versioned, labeled **real trace** dataset. Split by repository/scenario and time so near-duplicate executions cannot leak across train and test. Freeze feature extraction, model artifact and threshold. Calibrate the threshold on development data, then run one untouched held-out evaluation. Compare with the current deterministic rule signal and a simple baseline; publish ablations and false-block costs. Make activation an explicit configuration setting that records model hash and threshold in each receipt.

**Gate:** trained inference runs on live L3 observations, is distinguishable from the rule signal in API/UI, meets a documented benign false-block target, and fails safely when the model or feature pipeline is unavailable. If the target is not met, ship the rule signal only and report L4 trained detection as research.

**Where:** `l4_divergence/`, `agent_runtime/layer_report.py`, `agent_runtime/risk.py`, `benchmarks/`, `tests/integration/`.

## 6. Add independent L6 anchoring and key custody

**Build:** Continue local HMAC chaining and Ed25519 signing. Publish each final receipt digest to an independently controlled append-only/timestamped store; include the anchor reference and verification proof in the export. Keep signing keys outside the application data volume, support rotation and revocation, and require a separately pinned public key. Minimize/redact captured content before hashing or export.

**Gate:** an offline verifier checks the signature, complete audit digest, pinned key and external anchor without trusting the API host or a key bundled in the ZIP. Tests reject replaced keys, edited/deleted/reordered records, a forged timestamp/anchor, key rotation mismatch and loss of local state. Document what happens when the anchor service is unreachable; never report independent anchoring as successful in that state.

**Where:** `agent_runtime/evidence.py`, `agent_runtime/signing.py`, `agent_runtime/export_evidence.py`, `agent_runtime/verify_public.py`, `tests/gateway/`.

## 7. Implement hardware-backed L7 verification

**Environment:** Requires a supported TPM 2.0/TEE machine, its quote tooling and an independent verifier. The current user environment has no such host; contract tests and simulated quotes cannot close this gate.

**Build:** Define the approved measurement manifest for the actual loaded policy, collector/runtime, and active model. A verifier sends a fresh nonce; a hardware quote signs the relevant platform measurements and nonce. Validate the attestation key/certificate chain, measurement allowlist, freshness, run binding, and replay protection outside the measured host. Keep the existing software hashes as a separate, honestly labeled check.

**Gate:** genuine quotes pass on the named hardware; altered runtime/policy, stale nonce, wrong run, forged certificate and replayed quote fail. The UI sets `hardware_attested: true` only after the independent verifier returns success. Publish the supported platform and trust assumptions.

**Where:** `l7_trust/`, `agent_runtime/layer_report.py`, `tests/integration/test_l7_trust.py`, `docs/environment-support.md`.

## 8. Ship a reproducible, honest portfolio release

1. Keep the existing Python/FastAPI runtime, React/TypeScript/Vite UI, SQLite request ledger, Docker fixture, C/libbpf collector and cryptographic evidence components. Avoid a framework rewrite while the security gates remain open.
2. Reconcile `README.md`, `SECURITY.md`, the completion matrix, architecture diagram and dashboard labels with measured reality. In particular, separate the gateway's **live L4 rule signal** from a trained L4 model and **software L7 hashes** from hardware attestation. Archive or clearly label older AcademIQ simulated charts and overbroad threat-model wording.
3. Show a two-minute recruiter path: clean clone → `docker compose up --build` → Gateway fixture → denied `.env` before execution → download evidence ZIP → offline verification → current evaluation card. Record a short demo video with a visible commit and environment. Add an architecture diagram showing trust boundaries and where native/hardware stages are unavailable.
4. Run and retain the cross-platform gateway matrix, runtime/API, frontend build/test/lint, Compose configuration and Compose smoke in GitHub Actions. Native Linux and TPM jobs should be separate, gated by available runners and clearly marked unverified until they run.
5. For every reported metric, keep exact corpus version, trial count, model, source commit, host/kernel, dependency lock or image digest, command, raw private output location, sanitized public report and limitations. Rotate the previously shared Gemini API key and keep replacement credentials outside Git.

### Final acceptance checklist

- [ ] Fresh clone starts the credential-free app and passes `python -m scripts.compose_smoke`.
- [ ] Browser and API show the same allowed/denied decisions, audit status, EffectSeal status and seven-layer availability.
- [ ] Held-out repeated model evaluation reports both blocked side effects and useful benign completion, including failures and uncertainty.
- [ ] Restricted Docker fixture passes race, cancellation and cleanup checks on a named host.
- [ ] Native L3 is live only after request-scoped observation and complete-effect gates pass on supported Linux; otherwise it remains `INCOMPLETE`/unavailable.
- [ ] Trained L4, external L6 anchoring and hardware L7 are labeled live only after their independent gates pass.
- [ ] An offline reviewer can verify a downloaded receipt with an independently pinned key, and each resume bullet points to a reproducible artifact.

**Resume wording now:** “Built a task-scoped AI-agent tool gateway that blocks unauthorized file/tool actions before execution, records signed evidence, and runs a credential-free Docker/React demo; evaluated 50 held-out synthetic Gemini tasks with independently verified receipts and final-answer hashes.” State the exact 1/25, 0/1 and 25/25 results only with the single-trial, synthetic-corpus and lexical-check qualifiers. Do not claim a complete seven-layer production security system until the remaining live and independent gates above pass.
