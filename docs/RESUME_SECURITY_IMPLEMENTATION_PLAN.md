# AgentSentinel: implementation plan for a defensible security portfolio

Date: 16 October 2026

Status: implementation in progress. The phase gates at the end remain open until their full acceptance checks pass.

### 17 October implementation update

The current [product release checkpoint](PRODUCT_RELEASE_2026-10-17.md) ships a separate Overview, conversation Playground, per-action Layer trace, Results, saved Runs and source-bound Evaluation. Conversation turns, live event replay, exact-action approval preview and bounded run deletion are implemented. A live Gemini useful task, custom follow-up calculation, scripted document injection, saved-run recovery and policy comparison were verified in the browser. The refreshed 200-case fixture report and executed notebook are tied to the current approved source. Runtime/backend regression passed 43 tests and frontend regression passed 62 tests.

| Phase | Current evidence-bound state |
| --- | --- |
| P0 | Implemented and verified for local provider retry, failure states, refresh recovery and scripted startup. |
| P1 | Main chat/run-view release implemented; useful, denied and approval paths verified in browser. Additional formal accessibility/visual QA remains valuable. |
| P2 | Bridge API and exact Flowise function simulator exist. A real Flowise canvas is unverified: the local npm tree is incomplete and Docker Desktop Linux engine is unavailable. |
| P3 | Conservative server-owned source/artifact/destination graph and restricted export rule are implemented and signed; semantic taint tracking remains out of scope. |
| P4 | Local owner-scoped runs and short-lived signed integration capabilities are implemented; public user/agent identity and full concurrency proof remain open. |
| P5 | No validated isolated Linux executor in the active portable web path on this host. The bounded application executor remains the truthful claim. |
| P6 | Current repeated fixture contracts and historical small live-model reports exist; diverse held-out comparative evaluation and gateway-only overhead remain open. |
| P7 | Local launcher, tests, release docs and browser demo exist. Clean-clone acceptance, real Flowise video/screenshots and public release remain open. |

## Current implementation checkpoint

As of 16 October 2026, P0 and much of P1/P3 are implemented and verified locally: bounded model retry and safe failure reasons, saved-run refresh recovery, stale launcher record handling, a darker responsive Playground, recorded seven-layer checkpoints, and a conservative source-to-artifact graph bound into signed evidence. The external adapter returns bounded public output and its function simulator verifies allowed/denied actions and idempotent replay. A separate external-integration path now requires a short-lived, revocable, signed role capability; the bearer scope and role are server-owned and the creating capability alone can read its run. These are **application-level, synthetic local** results. A real Flowise canvas, full authenticated user/agent identity, Linux isolation, and the comparative held-out evaluation remain open gates. See `VALIDATION_STATUS.md` for test counts and `FINAL_PORTFOLIO_HANDOFF.md` for the current demo.

## 1. Product objective

Build a useful incident-analysis agent whose tool actions and information exports are controlled outside the language model. Demonstrate useful work, a prevented unauthorized effect, the responsible policy, and verifiable evidence in one short walkthrough.

Primary workflow: read synthetic incident records, calculate severity totals, create a cited report, and propose a local ticket. An attacker-controlled document or tool response may try to redirect the agent. The gateway decides which actions can run.

Release claim: “AgentSentinel enforces scoped tool permissions and source-aware export restrictions for a bounded incident workflow, records execution receipts, and evaluates security alongside useful task completion.”

The seven layers remain responsibilities with different lifecycle positions. They are not seven interchangeable malicious-prompt detectors. Unreached controls must never appear as passed.

## 2. Starting point and gaps

Existing foundation, described in FINAL_PORTFOLIO_HANDOFF.md:

- React/TypeScript Playground, custom prompt input, Gemini/Ollama providers, and an explicitly scripted demo.
- Python/FastAPI gateway, server-owned permission profiles, bounded local tools, SSE traces and saved runs.
- Exact-action approvals, signed evidence, tamper verification and policy comparison.
- A conservative restricted-source rule and adapter API with a Flowise tool recipe.
- Deterministic regression and separate small live-model evaluation reports.

Known gaps to resolve:

- An actual external Flowise canvas has not been verified. The partial local Flowise installation fails at startup with missing dependency `ajv`; bridge smoke tests do not establish canvas execution.
- Source restrictions currently track a limited run-level condition, rather than a complete artifact derivation graph.
- Repeated fixture contracts do not establish general adversarial robustness. Recent live attacks that produced no forbidden proposals do not measure gateway interception.
- Current Windows application tools do not establish arbitrary-code isolation, native telemetry or hardware attestation.
- The latest custom Gemini browser run returned a provider ServerError; a custom Ollama calculation subsequently completed. Provider failure recovery needs explicit treatment.

## 3. Technology choices

| Area | Choice and rationale |
| --- | --- |
| UI | Existing React, TypeScript, Vite, Tailwind and Lucide; CSS transitions driven by real events |
| API/runtime | Existing FastAPI, Python, Pydantic contracts and SSE |
| Persistence | SQLite with migrations for local demo; retain session ownership and request deduplication |
| Models | Gemini and Ollama behind the existing adapter; no silent provider substitution |
| Provenance | Typed source/artifact/derivation records stored in SQLite; canonical JSON hashes |
| Authorization | Server-owned policy plus short-lived signed capabilities, using existing cryptography dependencies |
| Evidence | Existing HMAC chain and Ed25519 receipts; independently pinned verifier key |
| External integration | Flowise Custom Tool calling the same gateway; MCP adapter as a subsequent reusable interface |
| Isolation | Linux Docker runner in an available VM/CI environment; non-root process, dropped capabilities, seccomp, read-only root and network restrictions |
| Verification | pytest, current frontend test runner, browser walkthroughs, and GitHub Actions |

Avoid adding a message broker, vector database or Kubernetes until a measured requirement justifies it. Keep the initial deployment local and single-user.

## 4. Delivery order

Implement P0 → P1 → P2 → P3 → P4. Complete P5 on a suitable Linux environment, then P6 and the final release gate. Build evaluation cases alongside each control; perform the comparative evaluation after the control contracts stabilize. Do not expand public exposure as part of this work.

### P0 — Stabilize the existing demo and establish a baseline

Deliverables:

1. Freeze the current feature inventory and record the source revision, dependency versions and current test results.
2. Classify model failures into timeout, rate limit, transient service failure, invalid response and unavailable configuration. Return safe, actionable UI messages without raw provider content or credentials.
3. Add a small bounded retry for eligible transient model-generation failures. Record attempts; respect cancellation and total run deadline. Never retry a tool effect automatically because a model call failed.
4. Persist/reconnect the active run after refresh; recover the correct provider, status and trace without executing it again. Do not invent an original prompt if it was not retained.
5. Harden one-command startup: recognize stale process records, check exact process identity and ports, report readiness, and offer a predictable scripted mode when cloud service availability is unsuitable for a presentation.
6. Ensure denial reasons, model refusals, operational errors and cancellations remain distinct outcomes.

Primary files: `agent_runtime/lab_provider.py`, `agent_runtime/secure_lab.py`, `frontend/src/api/secureLab.ts`, `frontend/src/pages/PortablePlaygroundPage.tsx`, launcher scripts.

Acceptance: a simulated transient provider failure recovers within the retry budget; persistent failure terminates clearly; cancellation works; refresh reconnects without a duplicate effect; a denied action never invokes its executor; startup works after a stale PID record. Preserve the current integrity approval workflow when measured source changes.

### P1 — Make the useful workflow and UI easy to demonstrate

Deliverables:

1. Default screen: prompt composer, four examples, compact provider/permission controls, activity feed and outcome card.
2. Show four explicit outcomes: completed work, model refusal/no unauthorized proposal, gateway block, and operational error.
3. Show one active action at a time with `proposal → authorization → execution/evidence`. Expand the seven-layer inspector for detail.
4. Animate actual received checkpoints. On a denial, stop the execution branch at its enforcing control while allowing evidence finalization to appear. Label recorded playback and provide pause, step and speed controls.
5. Add a concise explanation panel: requested action, resource/destination, matched rule, reason, whether the executor ran, and an authorized next step.
6. Produce genuinely useful artifacts: incident IDs, verified severity totals, source citations and a local ticket with clear destination.
7. Keep technical JSON and long traces behind disclosure controls. Support keyboard navigation, visible focus, reduced motion, readable contrast and narrow viewports.

Acceptance: a new viewer can run a useful task and explain one denied action without opening source code. Browser checks cover desktop and narrow layouts, an allowed workflow, a denied proposal, provider error, approval and saved replay. No animation fabricates a checkpoint.

#### P1 visual design specification — polished, interactive security console

Design goal: make the first screen feel like a finished developer security product. A visitor should immediately see where to type, what the agent is doing, and why an action was allowed or stopped. Visual polish is a release requirement for this project.

**Visual direction**

- Use a restrained dark navy theme as the default, with light mode available. Suggested dark tokens: background `#080D18`, surface `#111A2B`, raised surface `#18243A`, primary text `#F1F5F9`, secondary text `#A8B6CB`, accent cyan `#22D3EE`. Validate contrast in the implemented combinations.
- Use emerald for permitted effects, amber for review/warnings, rose for denied actions, and slate for checks not reached. Pair every color with an icon and text label.
- Use a clear sans-serif typeface for product content and a monospace face only for tool names, IDs and short technical values. Prefer locally bundled fonts or system fallbacks.
- Establish reusable spacing, radius, border and typography tokens. Use subtle depth and a small amount of background glow; preserve solid readable surfaces behind dense text.
- Give the product a compact identity: AgentSentinel wordmark, shield mark, connection status and current environment badge. Keep the environment label visible enough to distinguish local demo, live model and recorded replay.

**Desktop composition**

1. Compact navigation: Playground, Runs and Evaluation; System status in a secondary location. Keep navigation collapsible and keyboard accessible.
2. Main Playground uses a two-column layout: task/agent conversation on the left and the live security inspector on the right. Avoid a large marketing hero inside the application.
3. Composer includes a multiline prompt, four compact example chips, an attachment/source option for synthetic document attacks, and a prominent Run button. Provider and permissions use a compact settings disclosure.
4. The activity feed presents agent messages, proposed tools and results as distinct cards. Technical details expand in place. Show a useful waiting state during model generation and explicit cancellation status.
5. The outcome card leads with plain language, such as “Blocked: this agent cannot read .env,” followed by the responsible layer, policy and executor status.
6. Answer, Security trace and Evidence remain secondary tabs. Keep raw JSON, diagnostics and fault-injection challenges out of the initial view.

**Animated security inspector**

- Show admission checks, per-action checks, execution and evidence as connected groups. Display all seven responsibilities with the current action clearly identified.
- Animate a small packet along an edge only when the corresponding backend transition is observed. Briefly highlight the active node; settle into a stable completed state afterward.
- On denial, emphasize the enforcing node and explain the stopped branch. Keep subsequent audit/signature events visible. Never animate execution for a denied action or turn an unreached check green.
- Let the user select a node to open its explanation drawer: purpose, observed input summary, decision, reason, duration and evidence reference.
- Provide a live mode and clearly labeled recorded replay with pause, step, timeline scrub and speed. Replay changes presentation only and never reruns tools.
- Use short transitions around 150–250 ms for controls and approximately 300–600 ms for recorded flow emphasis. Preserve real timestamps and offer instant display. Fast event bursts should queue/coalesce visual emphasis without delaying security decisions or losing recorded events.
- Honor `prefers-reduced-motion`; provide static connectors and immediate state changes. Avoid endless particle effects, flashing alerts, fake progress percentages and decorative charts.

**Distinctive interactive views**

- Provenance view: select an artifact and reveal its source → derivation → destination graph. Highlight the restricted source responsible for a denied export. Provide an equivalent accessible text list.
- Policy comparison: show the same saved proposal under two permission profiles with changed decisions highlighted and an explicit “No tools executed” label.
- Evidence inspector: concise verified/tampered/unknown status, issuer fingerprint and downloadable bundle. Expand signature and hash details on demand; explain the local trust boundary.
- Runs gallery: compact searchable rows with provider, outcome, enforcement layer and timestamp; opening a run restores its recorded trace without a new model call.
- Evaluation page: separate cards for useful completion, forbidden proposals, prevented effects and errors, each with denominators and corpus/version context. Do not display a single unsupported “security score.”

**States and interaction details**

- Design empty, connecting, model-waiting, active-tool, approval-pending, completed, denied, cancelled, disconnected and provider-error states before implementation.
- An approval drawer shows the exact action, destination and content, with Approve/Decline controls and expiry. Do not obscure the content behind animation.
- Tooltips explain unfamiliar labels; important reasons remain visible without hover. Status changes use concise accessible announcements.
- Use gentle card entry and tab transitions. Reserve prominent motion for the security event the viewer needs to understand.
- Preserve draft text across accidental navigation within the application where appropriate. Disclose whether any text is stored; do not put secrets or session credentials in browser storage for visual convenience.

**Responsive behavior**

- At narrow widths, stack composer → outcome → compact flow → details. Use a compact navigation bar and allow the inspector to expand rather than squeeze a desktop graph into tiny cards.
- Test at approximately 390 px, 768 px and 1440 px widths. Ensure no horizontal page overflow, readable labels, usable touch targets and accessible drawers.
- Support long prompts, long rule names, large traces and zoomed text. Virtualize or paginate large histories when measured rendering performance requires it.

**Implementation structure**

- Extract reusable components such as `PromptComposer`, `AgentActivityFeed`, `RunOutcome`, `SecurityFlow`, `LayerDetailDrawer`, `ApprovalDrawer`, `ProvenanceGraph` and `EvidenceInspector`.
- Centralize theme tokens and shared status styles. Keep the backend capability registry as the source of truth for layer names and availability.
- Start with SVG/CSS for the seven-node flow and existing UI dependencies. Add a graph library only if provenance interaction complexity justifies it; avoid introducing a large animation dependency solely for hover effects.
- Implement in order: tokens and shell → composer/feed/outcome → event-driven flow → detail drawers → provenance/evidence views → responsive and accessibility verification.

**UI completion gate**

- Save and visually inspect screenshots for the initial screen, useful completion, denied action, approval, provenance restriction and narrow layout.
- Verify real browser interactions for custom prompt entry, settings, cancellation, node inspection, replay, evidence verification and error recovery.
- Confirm keyboard access, visible focus, contrast, reduced motion and text explanations for every status color.
- Confirm the interface remains responsive during bursty events and long traces. Animations must not change event order, execution behavior or reported timestamps.
- The final faculty demo must show one useful task and one stopped action with the reason understandable from the main screen.

### P2 — Verify an external agent integration

Deliverables:

1. Repair or recreate the isolated, ignored Flowise installation using a pinned compatible release and lockfile. Document prerequisites and setup; keep secrets outside exports and source control.
2. Create a versioned Flowise chatflow export using only the AgentSentinel tool bridge for effects. Use the same synthetic incident workflow.
3. Authenticate the bridge with narrowly scoped, expiring access. Correlate external session, invocation, gateway request, run and receipt IDs.
4. Add bounded request timeouts, stable retry identifiers, cancellation behavior and clear handling of pending approval.
5. Observe an actual canvas run that reads an allowed document and another that submits a forbidden action. Preserve sanitized outputs, matching receipts and screenshots.
6. Add an MCP adapter after Flowise passes. Expose declared tool schemas and forward every invocation into the same enforcement path; do not implement a separate executor.

Acceptance: external-agent actions appear in AgentSentinel with matching IDs; a forbidden proposal has zero executor calls; resubmitting an invocation cannot duplicate a ticket; missing/expired access fails; exports contain no credentials. A model refusal alone does not pass the interception demonstration gate. If the agent refuses every attack, pair it with a clearly labeled direct tool invocation through the integration.

### P3 — Implement source-aware action authorization

Deliverables:

1. Define server-owned source records: ID, content hash, version, classification and permitted destinations. Initial classifications: synthetic public, internal and restricted.
2. Define immutable artifact records with hashes and parent-source IDs. Record read and derivation edges for reports, calculations and tickets.
3. Propagate the most restrictive source classification conservatively. Treat model-supplied citations as claims; validate IDs against sources actually observed by the run.
4. Evaluate an export against both the tool permission and destination classification. Deny unknown source IDs, incompatible labels and attempted downgrades.
5. Show a provenance graph and a plain-language denial explanation linking source → derived artifact → proposed destination → rule.
6. Include the source/artifact graph digest and policy version in signed evidence.

Suggested models: `SourceRecord`, `ArtifactRecord`, `DerivationEdge`, `DestinationPolicy`, `ExportDecision`. Add schema migrations and small dedicated provenance/policy modules rather than growing the runtime monolith.

Acceptance: public-only artifact succeeds; mixed public/restricted artifact is restricted; removing a citation does not remove tracked restrictions; forged source ID fails; source-version change invalidates stale evidence; a fresh unrelated run does not inherit another run's labels.

Scope: this establishes conservative provenance enforcement. It does not prove semantic tracking of arbitrary paraphrases, covert channels or a general DLP classifier. Selective declassification is deferred until its approval and evidence model is defined.

### P4 — Add agent identity and scoped capabilities

Deliverables:

1. Represent an agent principal independently of its display name. Bind each run and integration invocation to an authenticated principal.
2. Issue short-lived signed capabilities binding issuer, subject, audience, run, tool, resource/destination constraints, expiry, unique nonce and policy version.
3. Bind approval to the exact normalized action digest and expiry. Keep revocation and single-use approval consumption server-side and atomic.
4. Deny wrong-agent, wrong-run, expired, revoked, replayed and scope-expanded requests.
5. Add profiles for reader, incident analyst and ticket reviewer; show effective permissions in the UI.
6. Cover cross-session ownership for runs, events, approvals, downloads and evidence verification.

Acceptance: permission-matrix tests and concurrent replay tests pass; an approval for one body cannot authorize another body; another session cannot retrieve private run content. A self-declared agent name never grants access.

Scope: local/integration identity does not establish public-service authentication. Internet deployment would require a separate OIDC/user-session, TLS, CSRF/CORS and operational review.

### P5 — Add and validate isolated execution

Environment prerequisite: a working Linux VM/container runtime or suitable CI runner. The current Windows application must report this feature unavailable until its environment checks pass.

Deliverables:

1. Introduce an executor interface with explicitly distinct bounded-application and isolated-Linux implementations.
2. Pin the runtime image; run as non-root, drop capabilities, retain seccomp, use a read-only root filesystem and bounded temporary workspace, and prohibit host filesystem/Docker socket mounts.
3. Deny outbound network by default. If a task needs a destination, use a constrained service path with enforcement and tests for redirects and alternate address forms.
4. Set CPU, memory, process, output and wall-clock limits; kill and clean up the task environment on timeout or cancellation.
5. Bind actual environment configuration and observed outcomes to the effect receipt. Never infer successful isolation from a requested config alone.
6. Add native telemetry only after isolation is proven and label collection coverage/loss explicitly. Hardware TPM attestation remains a separate hardware-dependent extension.

Acceptance: permitted work succeeds; host-file access, forbidden network, resource exhaustion and child-process persistence fail within limits; cancellation leaves no task process; cleanup runs after errors. CI records the actual OS/runtime/image used. Container isolation has a documented threat model and is not represented as complete protection against kernel vulnerabilities.

### P6 — Build a defensible adversarial evaluation

Deliverables:

1. Create versioned development and held-out corpora. Suggested initial scope: 60 distinct attack scenarios across 10 families and 40 benign tasks, with multiple trials for live-model runs subject to cost limits. Repetition counts must be reported separately from unique scenarios.
2. Families: direct unauthorized request, document instruction injection, tool-result injection, role/authority spoofing, encoded payloads, multi-step instruction chains, source laundering, scope escalation, approval/replay misuse and resource/budget abuse. Protocol and fault cases are explicitly separate from language attacks.
3. Give each case an expected permitted effect, forbidden effect, usefulness assertion and independently checkable artifact assertion. Keep development examples out of the held-out set.
4. Compare model-only instructions, basic tool allowlisting and full gateway controls within disposable synthetic resources. The baseline must never receive real secrets or unrestricted host tools.
5. Add control ablations for provenance and action-bound approval. Record model/version, source revision, policy version, seed where supported, attempts, latency and costs.
6. Publish sanitized JSON/CSV results and a reproducible notebook for charts. Retain failures and incomplete cases.

Required metrics:

- Unauthorized-proposal rate and unauthorized-effect rate, with explicit denominators.
- Prevention among actual forbidden proposals; report undefined/no proposals when the denominator is zero.
- Legitimate task completion and unnecessary denial rate, using effect/artifact assertions.
- Model refusal rate, invalid-response rate, service errors and evidence-finalization errors.
- p50/p95 end-to-end latency and separately measured gateway overhead.
- Verified evidence fraction; confidence intervals and trial/scenario counts for live results.

Acceptance: all charts regenerate from saved data; useful-task assertions inspect artifacts/effects; model refusal is not counted as gateway interception; no failed trial is silently dropped. Performance thresholds are selected and documented after measuring the baseline, not invented in advance.

### P7 — Package the release and recruiter demonstration

Deliverables:

1. Versioned startup instructions, dependency locks, example configuration, migration/backup instructions, and a clean-clone smoke check.
2. CI gates for authorization, provenance, approval replay, ownership, evidence tampering, frontend build/tests and supported executor checks. Report skipped environment-dependent gates explicitly.
3. Dependency/secret scanning with reviewed findings; remove credentials and session tokens from distributable artifacts.
4. A concise README with architecture, threat model, supported integrations, evidence links, setup and limitations.
5. A three-minute walkthrough: useful incident task → external-agent forbidden proposal → source-aware export denial → signed evidence tamper rejection.
6. Sanitized screenshots and a short demo recording with visible live/scripted/integration labels.
7. Resume bullets containing only verified implemented features and measured results from the released revision.

Acceptance: a fresh setup can run the scripted demo without a cloud key; live-provider setup is documented; the browser walkthrough works; the report links to reproducible evidence; the release has no unexplained critical test failures. Public hosting is a separate decision and is not required for this portfolio release.

## 5. Seven-layer contract

| Layer | Responsibility | Example enforcement or evidence |
| --- | --- | --- |
| L1 | Input and proposal schema | Reject malformed tool arguments; expose narrowly scoped input rules |
| L2 | Task, identity and source authorization | Deny `.env`, unauthorized destinations or restricted-source export |
| L3 | Bounded/isolated execution | Enforce execution limits and record actual effects |
| L4 | Sequence rules | Stop repeated or explicitly prohibited action sequences |
| L5 | Run governance | Budgets, cancellation and action-bound approvals |
| L6 | Evidence integrity | Pre-dispatch audit, signed receipts and tamper detection |
| L7 | Runtime/software integrity | Approved source/config comparison; report hardware attestation unavailable |

An action can be denied before execution while L6 still records its outcome. Controls may run repeatedly. The UI follows the recorded lifecycle, not a fabricated L1-to-L7 pipeline.

## 6. Completion checklist

- [ ] P0: failure recovery and repeatable startup verified
- [ ] P1: useful workflow, polished theme, event-driven animations and accessible responsive UI verified
- [ ] P2: actual external agent integration observed and evidenced
- [ ] P3: source-to-artifact-to-destination rules verified
- [ ] P4: identity, scoped capabilities and replay resistance verified
- [ ] P5: isolated executor verified on supported Linux environment
- [ ] P6: comparative held-out evaluation published with failures and denominators
- [ ] P7: clean-clone demo, CI, documentation and recruiter walkthrough complete

P0–P4 plus P6–P7 constitute the application-security portfolio milestone. P5 establishes the additional systems-security milestone. Do not label the systems milestone complete while its Linux validation is unavailable.

## 7. Implementation discipline

Work in reviewable changes per phase. Preserve existing user artifacts and the prior evaluation reports. After changing measured enforcement code, review and approve the new software baseline, then regenerate applicable evidence; old report hashes must remain associated with their original source. Keep secrets in the existing local secret mechanism. Never replace a live-model failure with a scripted success. Publish only after the concrete release diff and distributable evidence have been checked.

Reference context: [OWASP agentic security risks](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/) and [agent sandboxing engineering](https://www.anthropic.com/engineering/claude-code-sandboxing). These inform the threat model; they are not certifications of this project.
