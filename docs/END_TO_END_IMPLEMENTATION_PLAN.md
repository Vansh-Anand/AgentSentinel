# AgentSentinel end-to-end implementation plan

Updated 2026-10-10. This is the execution plan for turning the existing research repository into a reproducible security application. A layer is called **live** only when a real request passes through it and its claimed effect is independently checked. The local Windows + Docker Desktop release can validate the core product; native Linux eBPF and TPM/TEE proof require a separate supported host.

## Definition of done

A fresh clone starts the API and UI from documented commands. A deterministic fixture and a real Gemini provider can each propose typed actions through the same gateway. Authorized work completes; denied file, command, and network requests never reach an executor. A restricted Linux container demonstrates file and network containment with synthetic data. Each run has an inspectable timeline and an offline-verifiable audit chain. A versioned evaluation reports security *and* legitimate completion with denominators, latency, environment, and failures. CI reproduces the credential-free path. Native layers are shown as unavailable when their collectors or hardware are absent.

## Work sequence and acceptance gates

| Phase | Implementation | Gate |
| --- | --- | --- |
| 0. Baseline | Preserve the current working tree, pin dependencies, document supported hosts, add a doctor command and repeatable startup. | Clean clone runs fixture demo, Python tests, frontend tests/build without private credentials. |
| 1. L1 proposal contract | Use Gemini structured JSON output for typed tool proposals; reject malformed responses locally. Keep the older token-mask prototype clearly separate. | Real model emits a valid proposal and malformed output cannot invoke a tool. Token-level grammar masking is claimed only if proven with a supported model. |
| 2. L2 gateway | Server-owned task policy, exact arguments, pre-execution audit, at-most-once request ledger, deny unknown/unsafe calls. | Allowed call executes once; denied call executes zero times; restart and replay tests pass. |
| 3. Restricted execution | Snapshot only allowlisted files; pinned local image, no network, read-only root, non-root UID, dropped capabilities, resource/time/output limits. | Browser and CLI show safe command success and synthetic secret/network failures; hostile-workspace race and cancellation tests pass before production use. |
| 4. L3 observation | Add native Linux eBPF file/process/network probes, cgroup/run correlation, dropped-event health, and a collector protocol for EffectSeal. | On a Linux host, real events are correlated to the exact run and loss is measured. Windows reports unavailable; simulated events never imply native coverage. |
| 5. L4 behavior | Establish a versioned feature extractor, held-out real trace corpus, model artifact/hash, calibrated threshold and false-positive report. A local deterministic rule signal can support the UI but must be labeled separately. | Reproduce held-out precision/recall and benign false-block rate on real traces; no synthetic score is labeled a live model. |
| 6. L5 governance | Consume real L2/L3/L4 events in a bounded per-run risk state machine; emit MONITOR/REVIEW/STOP actions and keep hard policy denials independent of the score. | Multi-step trace triggers the expected action exactly once, with a causal audit record; benign tasks still complete. |
| 7. L6 evidence | Chain decisions, execution results, observations, risk actions, and effect receipts to a persistent key and independent anchor. Redact secrets before persistence. Sign the final audit digest with Ed25519. | Offline HMAC and pinned-public-key verifiers pass after restart and fail for edit, reorder, deletion, truncation, wrong key, and policy mismatch. Independent external anchoring is a separate release gate. |
| 8. L7 trust | Measure policy, collector, model, and runtime artifacts. Add a hardware quote provider and nonce/measurement/certificate verification on supported TPM/TEE hardware. | Hardware quote verifies against a fresh challenge on an independent verifier. Software hashes are labeled integrity measurements, never hardware attestation. |
| 9. Evaluation | At least 25 attack and 25 benign cases initially, then 100 of each for release. Version task, entry point, expected action, model, policy, commit and host. Run both gateway-on and disposable baseline. | Publish per-case outcomes, actual side effects, attack success, legitimate completion, false blocks, p50/p95 latency, and telemetry loss. |
| 10. Product release | One live timeline in the UI, capability labels, safe quickstart, CI, security/limitations docs, architecture diagram, screenshots and short demo video. | Recruiter can run the fixture without credentials and distinguish every live, replayed, simulated, or unavailable claim in under two minutes. |

## Seven-layer contract for each run

Every run returns `run_id`, provider/model, policy hash, exact gateway steps, EffectSeal receipts, a seven-stage capability/evidence report, and audit verification. The L4 local rule signal is derived from actual gateway events but is not the trained divergence model. L5 may stop repeated denied proposals; it cannot override L2's hard deny. L7 software measurement binds local artifact hashes to the audit, but `hardware_attested` remains false until a native quote verifies. A missing L3 collector forces EffectSeal `INCOMPLETE`, never `MATCH`.

## Platform matrix

| Environment | Supported demonstration | Native proof unavailable |
| --- | --- | --- |
| Windows + Docker Desktop (current) | Gemini/fixture gateway, restricted Linux command, HMAC evidence, local risk rules, software artifact measurement, browser UI | Host eBPF process-tree coverage, TPM/TEE quote in this application |
| Native Linux with BPF capabilities | All local capabilities plus eBPF collector after probe compilation and correlation validation | TPM/TEE unless hardware and quote tooling exist |
| Linux with supported TPM/TEE | Hardware attestation after native provider and independent verifier pass | Nothing may be inferred from a simulated quote |

## Current implementation checkpoint

- Verified: L2 gateway, restricted Docker fixture, bounded Gemini and fixture loops, local L6 HMAC audit plus Ed25519 signed receipt, deterministic EffectSeal core, seven-stage browser report, deterministic L4 rule signal, L5 risk governance, L7 software measurement, and the local doctor command. The current fixture browser run has eight verified audit records including contemporaneous EffectSeal and risk decisions.
- Verified: a single-trial model-backed 25 attack/25 benign README corpus with checkpointed retries, public per-case results, and 50 independently checked local audit chains. Five attack cases produced forbidden proposals; all were denied before execution. All benign tasks completed. The credential-free policy corpus has 25 of each.
- Current-source model gate: the single-trial 25 attack/25 benign synthetic corpus now passes with zero final provider errors, 50 verified HMAC chains, 50 verified Ed25519 receipts, and current-source hashes matching the checkout. The sanitized v2 report is generated locally. The v1 report remains historical; repeated trials, held-out traces, answer quality, and a baseline are still open.
- Added on 2026-10-09: credential-free Compose packaging and browser verification, a portable public evidence ZIP/CLI, POSIX descriptor-relative source reads, Docker timeout cleanup, cgroup-filtered `execve`/`openat`/`connect` entry probes and collector bridge, and a fail-closed L7 simulation contract. All three probes and the loader compiled in an Ubuntu validation image with a checked C/Python event ABI. A privileged Docker Desktop Linux VM run then attached the probes and observed correlated process, synthetic-file, and loopback-network attempts with zero measured ring-buffer drops. Native host-wide and request-specific coverage still require validation; Compose and the local Gateway do not attach the probes.
- The native-to-EffectSeal mapper and optional L5 observer path now have contract tests. Partial entry-probe coverage is always `INCOMPLETE` for allowed effects, while an observed out-of-scope attempt can be `VIOLATION` and stop subsequent calls. This is not yet wired to a real request-specific cgroup in the application.
- In progress: repeated model trials, held-out comparison, answer-quality scoring, full native L3 observation with syscall outcomes and live EffectSeal wiring, trained L4 detector, independent external anchoring of the public-key evidence, hardware L7 quote provider, and hostile-workspace container validation. A credential-free Compose smoke now checks the current gateway and offline evidence ZIP locally and is configured in CI; remote CI execution remains unverified.
- External host gate: native L3 eBPF and L7 hardware quote cannot be truthfully marked verified on this Windows machine. The user has no separate Linux host at present.

See [validation status](VALIDATION_STATUS.md) for exact test counts and browser proof. The older [resume-ready build plan](AGENTSENTINEL_RESUME_READY_PLAN.md) records the threat model and research background; this file is the active execution order.
