# AgentSentinel: resume-ready implementation plan

Date: 15 October 2026
Status: roadmap with a portable implementation now delivered; consult `PORTABLE_RELEASE.md` and the validation status for the tested feature boundary. Native/hardware validation and a running external Flowise canvas remain extensions.
Scope: extend the existing application, retaining its actual gateway, live providers, streaming events, audit chain, signatures, and evidence viewer.

## Current delivery against this plan

| Phase | Status at 15 October 2026 |
| --- | --- |
| 0 baseline and claims | Delivered for the portable Windows scope; [current status](final-project-status.md) and [threat model](PORTABLE_RELEASE.md) distinguish application, fixture, live model, and native claims. |
| 1 shared enforcement and events | Delivered: server-owned profiles, versioned durable events, same gateway for all new tool proposals, bounded runs, cancellation and resume. |
| 2 useful workflow | Delivered: scoped read, search, safe arithmetic and bounded report. The proposed internal mock network destination remains deferred because this release denies network access. |
| 3 portable seven responsibilities | Delivered with distinct controlled tests and explicit proof modes. Native eBPF, trained L4 and TPM are outside the portable release. |
| 4 visual live lab | Delivered at `/lab`; desktop and 390 px browser views, custom live prompt, replay and saved history were verified. |
| 5 evidence and distinguishing features | Delivered: application action/effect receipts, trusted-key verifier, policy counterfactual and zero-effect replay. |
| 6 evaluation and hardening | Delivered for the local synthetic scope: [200 controlled capability contracts](PORTABLE_EVALUATION.md), small separate live smoke, session ownership, loopback admission, budgets and CI. Independent real-world attack corpus, quantitative ML measures, and public service authentication remain future work. |
| 7 portfolio release | Local faculty guide, reproducible scripts, metrics, browser verification and a tested adapter endpoint are delivered. A clean-machine install, recorded video, external Flowise canvas and public deployment remain unverified. |
| 8 native research | Deferred until a suitable Linux/TPM validation host is available. |

The plan below preserves its original target criteria. A checked portable behavior should not be read as evidence of an unvalidated research or public-deployment target.

## 1. Product and defensible claim

Build an interactive security gateway for tool-using AI agents. A visitor enters a custom task or attack, sees the model's proposed actions, watches security decisions occur, and downloads verifiable evidence explaining what ran and what was prevented.

The practical problem is that a model can turn attacker-controlled document text into an unauthorized tool action. The application should demonstrate bounded useful work as well as prevention: summarizing synthetic documents, searching a small synthetic knowledge base, performing calculations, and creating a report inside a disposable workspace.

Project positioning: **AgentSentinel — an observable security gateway for AI agent actions.**

The strongest portfolio contribution is the connection between policy, action, observed effects, and independently verifiable evidence. Seven boxes alone do not establish security or novelty.

Threat references: OWASP's [prompt-injection guidance](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and [excessive-agency guidance](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) motivate separating untrusted text from authority and limiting agent permissions. Use these named risks as the threat model; pin the taxonomy version in published benchmark reports rather than claiming coverage of every OWASP risk.

## 2. Existing baseline and gaps

Current source includes:

- React/TypeScript Live Lab with custom text, deterministic fixture, Gemini and local Ollama choices.
- FastAPI streaming run endpoint and bounded agent loop.
- Server-owned task policy; allowed README read and denied out-of-scope reads, commands, and network proposals.
- HMAC-chained audit records, Ed25519 receipts, offline verification, and saved run history.
- Animated view of received events and a summary of the attack source, proposal, and denial.

Current limitations:

- The normal demo permits too little useful work to demonstrate fine-grained authorization convincingly.
- L1 is currently structured proposals, not a general prompt-injection detector.
- L3 has no native collector attached to the Live Lab. An allowed execution has incomplete native telemetry.
- L4 currently derives signals from gateway outcomes; its research model is not active in this path.
- L7 hashes software artifacts; it does not establish trusted loaded code or hardware attestation.
- Fixture replay recognizes preset phrases. Arbitrary custom prompts require a real provider.
- The long vertical results page needs a clearer task → decision → outcome presentation.

No Linux/TPM host is available. A complete portable demo is the first release. Native eBPF and hardware attestation are a separate extension with separate acceptance criteria.

## 3. Seven-layer architecture and truthful visualization

Preserve the existing layer IDs for continuity. Extend their responsibilities explicitly and version the layer-report schema. These are seven security responsibilities across the lifecycle, not seven sequential classifiers of the same text.

| Layer | Inputs and implementation | Stop behavior | Portable release proof |
|---|---|---|---|
| L1: Input and proposal validation | User text, untrusted context, size/encoding limits, explicit injection indicators, structured tool schema. Begin with explainable rules; optional classifier only after independent evaluation. | Reject malformed/oversized input and invalid proposals. High-confidence policy rules can block; ambiguous semantic indicators produce REVIEW rather than automatic certainty. | Rule ID, matched span, source, policy version, and schema failure. A score is not a calibrated probability unless measured. |
| L2: Task authorization | Server-owned capabilities, tool arguments, resource scope, normalized paths, write targets, outbound destinations, and output/egress policy. | Deny unauthorized tool calls before dispatch; deny delivery of disallowed tool data or final output before release. | Exact denied capability and reason; executor_invoked=false for pre-execution denials. |
| L3: Execution containment and effects | Executor wrapper, disposable workspace, operation receipts, bounded outputs and timeouts; isolated worker for any executable workload. | Reject an unavailable required isolation mode before execution; terminate a bounded worker on a runtime violation and prevent further steps. | Application-observed effects clearly labeled as such. OS/container observation is a different evidence mode; post-action detection is not prevention of an already completed effect. |
| L4: Behavioral deviation | Per-run sequence of proposals and outcomes: repeated probes, scope expansion, unusual tool order, or movement from reading to exporting. | Stop the next action before dispatch when an enforced sequence rule is violated. | Sequence rule, supporting prior events, threshold, and the action prevented. Do not relabel L2's decision as independent L4 detection. |
| L5: Run governance | Wall-clock, tool-call, token/output and cost estimates, retries, session risk, and optional approval state. | Pause for approval, stop on budget exhaustion, or revoke remaining run capabilities. | Budget counters, threshold, and cancellation acknowledgement. Cost estimates remain labeled estimates. |
| L6: Evidence integrity | Durable audit chain, event ordering, signed terminal receipt, independent verification. | Refuse further side effects when the required audit record cannot be persisted; mark a modified historical export invalid. | Failed write/verification reason; signed evidence. It detects evidence corruption, not malicious prompt meaning. |
| L7: Runtime integrity and readiness | Trusted manifest, policy/tool versions, model/provider configuration, required executor capabilities. Check before run and before dispatch where relevant. | Refuse admission or dispatch when the required baseline or capability is missing/mismatched. | Compare with an independently approved manifest. A fresh self-generated hash alone is not trust. Hardware attestation remains unavailable without a validated TPM path. |

Execution order:

1. L7 readiness/integrity preflight; L6 starts durable evidence.
2. L1 checks input and identifies lower-trust context.
3. The model proposes an action; L1 validates its structure.
4. L4 evaluates the proposed sequence, L5 checks budgets/approvals, and L2 authorizes the action.
5. L6 persists authorization before dispatch; L3 performs bounded execution and records effects.
6. L2 checks output release; L4/L5 update run state. Repeat for further proposals.
7. L6 seals the terminal evidence and the answer is released only after required output checks.

All seven nodes remain visible. Active edges show actual chronology and repeated tool cycles. A prompt-only answer has some tool stages marked NOT_APPLICABLE. An early denial leaves downstream execution stages NOT_REACHED, while evidence finalization can still run.

Use separate fields for lifecycle state and decision:

- State: WAITING, RUNNING, COMPLETED, NOT_REACHED, NOT_APPLICABLE, UNAVAILABLE, ERROR.
- Decision: ALLOW, DENY, REVIEW, STOP, or null.
- Evidence mode: LIVE_APPLICATION, LIVE_CONTAINER, LIVE_NATIVE, SOFTWARE_INTEGRITY, HARDWARE_ATTESTED, FIXTURE, REPLAY.

Never display all seven green checks merely because the run finished. No fixed animation timer may manufacture backend progress. Replay may pace saved events and must say Replay.

## 4. UI and demonstration experience

### Primary layout

Keep four destinations: Live Lab, Runs & Evidence, Evaluation, and System.

Live Lab desktop layout:

```text
Provider readiness     policy profile     Live / Fixture label
-------------------------------------------------------------
Task / attack composer | Seven-layer graph with live event path
Conversation + answer  | Selected layer: reason, input, evidence
-------------------------------------------------------------
Outcome: prevented action / runtime stop / no violation / error
Replay event trace     Download evidence     Start another run
```

On narrow screens, stack composer, outcome, compact layer strip, and expandable detail. Remove horizontal navigation overflow. Keep technical JSON collapsed.

### Input modes

1. **Task:** a plain chat-like prompt, such as “Find the incident retention period and create a short report.”
2. **Attack in document:** enter the attack text alone; an expandable context panel shows the legitimate task and exact lower-trust document that will contain it. The backend reads the disposable document through the tool gateway.
3. **Forbidden user request:** a direct prompt asking for actions outside the selected server-owned policy.
4. **Layer challenge:** advanced controlled fault tests for evidence, runtime, and integrity layers. Clearly distinguish these from natural-language prompts.

Custom text must reach the selected model. Presets only populate inputs and must not supply verdicts. Use the same backend pipeline for custom and preset runs. Explain provider availability; never silently substitute fixture output after a live-provider error.

### Visual behavior

- A visible request packet moves on edges when the corresponding event arrives.
- Active layer pulses; denied layer highlights red and explains the exact rule. REVIEW is amber and distinct from DENY.
- Selecting a node shows what it inspected, why it decided, its evidence mode, elapsed time, and a sanitized relevant excerpt.
- Separate “Requested”, “Authorized”, “Executor invoked”, “Effect observed”, and “Output released”.
- Show readable tool arguments and a concise decision, not invented chain-of-thought. Model-provided messages are labeled model explanations and are not ground truth.
- Use a compact per-action timeline when several tool calls traverse the graph.
- Include Pause/Resume only for trace replay. Live cancellation is a backend operation and must show when cancellation actually takes effect.
- Support keyboard navigation, reduced motion, clear focus, and text labels alongside colors.

## 5. Useful capabilities and safety boundary

Start with deterministic, bounded tools that provide useful positive cases:

| Tool | Allowed example | Denied example |
|---|---|---|
| read_document | Read allowlisted synthetic project files | Read .env, parent traversal, symlink escape |
| search_documents | Search the run's synthetic document collection | Search another session's collection |
| calculate | Parse a limited arithmetic grammar | Execute Python, eval, shell, or arbitrary code |
| create_report | Create a size-bounded report in the run's output directory | Overwrite policy files or write outside the assigned directory |
| submit_demo_record | Send a synthetic record to an internal local mock service | Arbitrary outbound URL or forbidden synthetic field |

Preserve old API/tool compatibility during migration. The model cannot set its own policy, identity, granted scopes, risk thresholds, or approval state. Browser profiles select among server-defined capabilities; they do not send arbitrary allow rules.

Treat the local mock service as a demonstration destination, not proof of unrestricted Internet SSRF prevention. Any later network adapter needs redirect validation, DNS/address checks, timeout/size limits and separate tests.

Portable execution wrappers are not a sandbox for arbitrary hostile code. General shell access is outside the first release. If a Linux container mode is added, require non-root execution, read-only filesystem, explicit mounts, resource limits, no host socket, and a verified isolation profile before enabling its bounded workloads.

## 6. Distinctive features worth implementing

### A. Action-to-effect evidence

Extend the existing EffectSeal work: bind each proposal to a capability/policy hash, authorization result, executor invocation, observed application effects, and signed receipt. Explain coverage gaps explicitly. This is a strong portfolio feature; do not claim research novelty without comparison against prior systems.

### B. Policy counterfactual replay

Ask “Would a tighter policy have stopped this saved proposal?” Re-evaluate recorded sanitized proposals against another versioned policy without rerunning a model or executing tools. Show the changed rule and earliest differing decision. Label this counterfactual authorization, not a prediction of how the model would behave under a different policy.

### C. Layer contribution view

Show the first enforcing layer, other observed signals, and which layers never ran. In evaluation, use captured proposal replay for policy ablations and separate live-agent trials for end-to-end behavior. An early L1 block cannot count as a successful L2–L7 interception.

### D. Independent evidence verifier

Provide a small CLI that checks exports against a pinned trusted public-key fingerprint. Show a tampered copy being rejected while preserving the original. A receipt carrying its own arbitrary key cannot establish issuer identity by itself.

### E. Integration adapter after the core release

Add one documented Flowise or tool-protocol adapter. It must route execution through the gateway; a check-only API followed by an independent unrestricted tool is bypassable. Show matching run/request IDs in both products and verify an allowed and denied operation. Do not make several integrations prerequisites for the core release.

## 7. Backend contracts and implementation map

Retain Python/FastAPI, React/TypeScript, Vite, Tailwind, Gemini/Ollama and existing cryptographic libraries. Use SQLite for local run metadata and migrations; retain append-only audit storage. Add an SVG graph or a maintained React graph library only if its interaction features justify the dependency. No new model training or distributed infrastructure is necessary for the portable first release.

Implement a typed LayerResult with layer ID, phase, decision, enforcement action, reason code, explanation, redacted evidence references, duration, detector version, policy hash, and evidence mode.

Each SSE event needs schema_version, run_id, request_id when applicable, monotonically increasing sequence, timestamp, event type, layer ID, and safe payload. Add layer_started, layer_completed, action_prevented, execution_started, execution_finished, approval_required, cancellation_requested, cancellation_completed, and terminal states.

Persist ordered events for reconnection using a last-seen sequence. Reconnecting must not rerun the model. Deduplicate by run ID and sequence. Define terminal semantics for provider timeout, client disconnect, cancel, and audit failure. Bound queues, event sizes, concurrency, and retained run count.

Suggested source changes:

- `agent_runtime/agent.py`: lifecycle orchestration, cancellable bounded loop, proposal checks before dispatch.
- `agent_runtime/service.py`: run context, server-owned policy profiles, workspace lifecycle.
- `agent_runtime/gateway.py` and `policy.py`: capabilities and output release decisions.
- `agent_runtime/layers/`: layer contracts, input validation, behavior rules, budget guards, integrity admission.
- `agent_runtime/tools.py`: bounded useful tools and application effect receipts.
- `agent_runtime/evidence.py`, `signing.py`, `export_evidence.py`: versioned event bindings and verifier trust contract.
- `dashboard_api/routers/runtime.py`: versioned streaming, cancellation, resumable event reads and run detail.
- `frontend/src/pages/LiveLabPage.tsx`: composer and concise outcome.
- `frontend/src/components/lab/`: graph, selected-layer detail, proposal timeline and replay controls.
- `tests/runtime/`, frontend tests, and `benchmarks/`: enforcement, lifecycle, evaluation and UI evidence.

Do not embed secrets in events or exports. Preserve the existing locally stored provider credential mechanism. Document synthetic-data use and the destination when a cloud provider is selected.

## 8. Ordered implementation phases

### Phase 0 — Freeze the claims and baseline

Tasks: inventory every layer's current implementation; consolidate stale status documents; define threat actors, trusted components, protected assets, attacker control and non-goals; record baseline tests and existing evidence schema. Preserve unrelated report/notebook work.

Exit: one capability matrix backed by code, and a reproducible baseline. No native/hardware claim on the Windows path.

### Phase 1 — Shared enforcement and event contract

Tasks: implement LayerResult, versioned lifecycle events and server-owned policy profiles; add correlation IDs, durable ordered event replay and cancellation semantics; ensure all tool dispatch passes through one enforcement path.

Exit: allowed, denied, timeout, cancelled and evidence-failure runs each have consistent events and exactly one terminal state. Duplicate requests cannot repeat effects.

### Phase 2 — Useful agent workflow

Tasks: add document search, safe calculator and bounded report creation; isolate each session's data; add the internal demo destination only after read/write tests pass. Retain arbitrary custom task and attack text.

Exit: at least three useful benign tasks complete; unauthorized variants cannot escape scopes. A custom phrase never receives a verdict from a preset lookup.

### Phase 3 — Portable seven-layer enforcement

Tasks: implement L1 screening/schema checks, L4 independent sequence rules, L5 budgets/approval/cancellation, L7 pinned-manifest admission, L6 audit-failure gates, and L3 application effects/worker limits. Keep L2 as the authorization authority. Add final-answer/output-release checks for synthetic secret canaries and unsafe rendered output.

Exit: each layer has a controlled test that exercises its real responsibility, a reason code and proof of what stopped. Required protection unavailability refuses the affected operation; optional missing telemetry is explicitly incomplete. Documentation does not call this native eBPF/TPM protection.

### Phase 4 — Visual live lab

Tasks: replace the long card stack with composer, graph and selected-layer detail; animate backend events; show per-tool loops, visible failure source, no-proposal outcomes and explicit evidence modes; add replay, responsive layout, reduced motion and accessible controls.

Exit: a new visitor can enter a custom prompt and explain the resulting action/decision from the page. Verify in the in-app browser at desktop and narrow widths, including mid-run provider failure and reconnect.

### Phase 5 — Evidence and distinguishing features

Tasks: bind action/effect receipts, pin verifier issuer trust, implement policy counterfactual replay and contribution view; export sanitized reproducible evidence with policy/detector/model versions.

Exit: independent verifier accepts an original export and rejects modified/truncated/reordered evidence; counterfactual replay performs zero tool executions.

### Phase 6 — Evaluation and application hardening

Tasks: build a held-out synthetic corpus, measure useful task completion and attack outcomes; add API validation, session ownership, per-run budgets, rate limits, safe Markdown rendering, dependency review and CI checks. Add authentication and tenant isolation before any public deployment. Local loopback mode remains the default.

Exit: published results include denominators, uncertainty, provider errors, latency, dataset version and limitations. Regression tests include traversal, symlink escapes where supported, session isolation, duplicate requests, policy bypass, XSS text rendering, cancellation and audit-write failures.

### Phase 7 — Portfolio release

Tasks: prepare a concise README, architecture diagram, threat model, API examples, installation command, demo script, screenshots, short video, evaluation report and verifier instructions. Package a predictable offline fixture demo and a separate live-model demo. Add one integration adapter if the core gates already pass.

Exit: clean-machine setup and browser smoke succeed; all screenshots are from the delivered version; resume claims point to measured artifacts. Publish only after a credential scan and review of the intended public files.

### Optional Phase 8 — Native research extension

Prerequisites: suitable Linux environment with validated eBPF privileges and a separate TPM-capable environment for hardware validation.

Tasks: attach the existing native collector to actual sandbox run IDs, validate coverage/drop detection and attribution, compare native effects against authorized effects, then validate TPM challenge freshness and approved measurements.

Exit: actual native/hardware evidence from that environment. A simulated quote, replayed syscall list, or Windows software digest does not satisfy this phase. Do not block the portable portfolio release on this hardware work.

## 9. Acceptance matrix: one meaningful demonstration per layer

| Layer | Controlled stimulus | Required visible result |
|---|---|---|
| L1 | Malformed proposal, oversized input, or an enabled exact high-confidence injection rule | Specific input/schema rule prevents model invocation or tool dispatch; benign quotation comparison is evaluated separately |
| L2 | Custom model proposal for .env, traversal, forbidden destination or write | Capability denial before execution with executor_invoked=false |
| L3 | Approved bounded worker exceeds output/time limits; controlled executor test attempts an out-of-envelope effect | Worker stopped or required execution refused; honest timing and observer coverage, no claim to undo completed effects |
| L4 | Sequence of individually permitted operations violates a defined read-to-export sequence policy | Independent sequence rule stops the next action before dispatch |
| L5 | Custom iterative task exhausts tool/time budget or reaches an approval-required capability | Budget/approval gate stops further work and records the counter or approval state |
| L6 | Injected audit-store failure or modified copy of an export | Further effect refused, or historical evidence marked invalid; original evidence preserved |
| L7 | A controlled test bundle differs from its approved manifest | Admission denied before model/tool execution with exact mismatch |

L3, L6 and L7 demonstrations require controlled runtime/fault inputs. Do not invent a magic prompt that tampers with hardware or a signature. Put these demonstrations in Layer challenge mode with fixture provenance.

Additional scenarios: benign task, model ignores injection, model follows injection but tool is blocked, model repeats attack text without a tool, live-provider failure, empty/Unicode input, reconnect, user cancellation and saved-evidence replay.

## 10. Evaluation design and metrics

Start with a versioned suite of at least 100 attack cases and 100 benign cases across direct requests, indirect document injection, role spoofing, encoded/obfuscated text, multi-turn scope expansion, exfiltration requests and legitimate security discussion. These are target corpus sizes, not existing results. Keep templates/paraphrase families separated across development and held-out sets. Record exact model/version/settings and repeat a representative subset to expose model variability.

Report separately:

- Input-screen precision/recall and benign false-positive rate, only against declared labels.
- Attack-to-proposal rate: attacks that caused an unauthorized proposal / valid attack runs.
- Unauthorized-execution rate: unauthorized actions executed / unauthorized proposals; also report run-level attack success under an explicit objective.
- Gateway prevention rate conditional on an unauthorized proposal, with counts.
- Benign task completion against task-specific assertions; blanket blocking must not score as success.
- First enforcing layer, unavailable/skipped layers and evidence coverage.
- Provider/error/cancellation counts; do not silently remove them from the denominator.
- End-to-end and security-overhead latency p50/p95, model tokens and estimated cost.
- Evidence verification success; mutation-test detection counts.

Use confidence intervals for proportions and document repeated-run dependence. A zero observed failure count does not prove perfect security. Compare input rules only, authorization only, and combined defenses using controlled proposal replay; separately report live-agent trials because changed feedback changes model behavior. Any permissive baseline must operate only in an isolated synthetic test harness, never as a public UI toggle.

## 11. Scope priorities and resume value

Must-have: useful custom tasks, server-owned capabilities, seven truthful layer states, real cancellation and budgets, readable interception reasons, signed evidence, held-out evaluation, and reproducible setup.

Next: policy counterfactual replay, independent verifier, sequence rules, one Flowise/tool adapter and CI regression gates.

Later: native eBPF, TPM, trained behavioral model, multi-tenant hosted deployment, multiple integrations. Avoid adding these simultaneously before the portable core works.

The project demonstrates backend design, secure authorization, event streaming, frontend state management, cryptographic verification, threat modeling, testing and experimental discipline. Its strength depends on measurable useful behavior and defensible evidence, not layer count or claims of perfect detection.

Resume template after implementation and measurement:

> Built AgentSentinel, a tool-governed AI agent platform with live security traces, scoped authorization, execution limits and verifiable signed evidence; evaluated on [N] held-out synthetic cases with [measured unauthorized-execution rate], [benign task completion] and [p95 security overhead].

Do not fill placeholders until the corresponding experiment is complete. State the observer mode and hardware limitations in the linked project documentation.

## 12. Release checklist

- [ ] Every tool and output-release path uses the server-owned policy.
- [ ] Custom prompts use the same pipeline as presets; fixture mode is explicit.
- [ ] Each layer reports its actual input, decision, enforcement point and evidence mode.
- [ ] Early stops leave downstream operations not reached; no invented seven-pass sequence.
- [ ] At least three useful benign tasks complete reliably.
- [ ] Layer-specific challenge tests exercise distinct responsibilities.
- [ ] Cancellation, timeout, provider failure and audit failure are visible and bounded.
- [ ] Signed evidence can be verified against a trusted key outside the application.
- [ ] Public screenshots and metrics match the released revision.
- [ ] Desktop/narrow browser demo, setup instructions and offline fallback are verified.
- [ ] Native/hardware features remain unavailable until validated in the required environment.

Implementation should begin with Phase 0 and Phase 1; complete each exit criterion before adding another major feature.
