# AgentSentinel: Resume-Ready Build Plan

**Plan date:** 2026-10-07<br>
**Project goal:** Turn the existing AcademIQ research prototype into a demonstrable security product that prevents prompt-injection-driven tool misuse by an AI coding agent.<br>
**Primary audience:** Software engineering and cybersecurity internship/job reviewers.

## 1. The project in one sentence

AgentSentinel is a task-scoped tool gateway for AI coding agents: it checks every proposed file, command, and network action before execution, runs permitted actions inside a restricted environment, and records verifiable decisions.

### The real problem

An agent working on a legitimate task can encounter attacker-controlled repository files, web pages, or tool responses. Those inputs can persuade it to read secrets, run harmful commands, or send data to an attacker. This is an agent goal-hijack and tool-misuse problem identified by the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). OpenAI's [prompt-injection research](https://openai.com/index/designing-agents-to-resist-prompt-injection/) recommends limiting the effect of a successful manipulation at the action boundary. Its [Agents SDK guidance](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals) places checks next to side-effecting tools and uses approval for sensitive actions.

### The promise to prove

> Given a legitimate repository task and an attacker-controlled README containing instructions to steal a secret, AgentSentinel allows the legitimate work but prevents the secret read and outbound transfer, with an auditable record of the proposed actions and decisions.

This is a narrower, testable claim than “stops all prompt injection.”

## 2. Current baseline and the gap

| Existing asset | Keep and use it for | Current limitation to address |
| --- | --- | --- |
| `l1_gcd/` grammar and Hugging Face adapter | Optional constrained-generation demonstration | The dashboard/orchestrator path checks a constructed string after a tool call is proposed; it is not generation-time control in that path. |
| `l2_sdn/` parser, normalizer, and policy matcher | Defense against obfuscated shell commands | `ExecutionGate` returns a decision but does not own real execution. Its path check precedes the placeholder execution point. |
| `l3_ebpf/`, `l4_divergence/`, `l5_riskchain/` | Research extensions and offline/replay analysis | The default orchestrator path synthesizes telemetry and risk outcomes; the dashboard uses heuristic deeper-layer outcomes. Do not label them live enforcement. |
| `l6_eces/` evidence chain and SQLite store | Audit log and forensic export | The signer is regenerated when the orchestrator starts; verification needs stable trust material and an external chain-head anchor to detect database replacement/truncation. |
| FastAPI dashboard and React frontend | Demo and reviewer experience | Present actual gateway decisions separately from simulation, synthetic benchmarks, and replay. |
| Existing experiments and reports | Seed attack cases and document research history | Existing 20/20 and similar results apply to their defined datasets; they are not evidence of broad real-world prevention. |

**Repository hygiene:** The public repository is named `AgentSentinel`, while code and documentation largely say `AcademIQ`. Choose `AgentSentinel` as the product name and explain AcademIQ as the earlier research prototype, or consistently keep one name. The current workspace also contains uncommitted work; preserve and review it before changing those files. No existing work should be discarded to follow this plan.

### How the seven layers fit the resume-ready release

Keep the seven-layer architecture as a roadmap and research lineage. Recruiter-facing claims must follow what executes in the demonstrated path, not what has a module or UI card. The release target is **live L2 policy enforcement plus L6 evidence**, with a real agent/tool boundary and a restricted executor. Add L1, L3, L4, L5, and L7 to the live claim only when their individual proof gates below pass.

| Layer | Release role | Proof gate before calling it live |
| --- | --- | --- |
| L1: grammar-constrained decoding | Optional model-specific prevention; keep the Hugging Face adapter as a separate demonstration until connected to the selected agent model. | Show a model's actual token generation constrained by the policy, and distinguish this from post-generation tool-call validation. |
| L2: semantic command defense | Core live prevention, routed through the new pre-execution gateway. | A real proposed call reaches L2, a denied call never reaches the executor, and an allowed call executes exactly once in the sandbox. Test obfuscated and compound commands. |
| L3: eBPF telemetry | Optional Linux detection/visibility after the core release. | Native probe attaches, consumes real events, maps them to the correct run/cgroup, measures dropped events, and shows what is observation versus enforcement. |
| L4: behavioral divergence | Research signal until evaluated on independent real traces. | Show held-out detection and false-positive results on real benign/attack traces, model versioning, and drift handling. Never present synthetic scores as live measurements. |
| L5: risk-chain governance | Optional live escalation after multi-step event wiring. | Demonstrate that real L2/L3 events update risk state and cause a policy action; remove heuristic dashboard-only stopping layers from the live path. |
| L6: cryptographic evidence | Core audit capability, integrated with gateway requests and execution outcomes. | Verify a complete real run across restart, with stable key identity and tests for edit, deletion, reordering, and truncation against an independent anchor. |
| L7: TPM/TEE attestation | Long-term research extension. | Obtain supported hardware, verify real quotes/measurements and isolation, and document the exact trust boundary. Otherwise label unavailable/scaffolded. |

This sequencing keeps the technical ambition while giving a hiring reviewer a claim they can reproduce. More layers can become live later without changing the product's central problem or overstating the current release.

## 3. Scope and threat model

### First supported workflow

- A coding agent receives a user request to inspect or summarize a repository.
- The agent reads repository content that may contain attacker instructions.
- The agent can propose only three structured tool types in the first release: `read_file`, `run_command`, and `http_request`.
- AgentSentinel evaluates each proposed call before the tool executes and records the outcome.
- The runnable demo uses a Linux container, including when launched from Windows through Docker Desktop.

### Trust boundaries

| Trusted for the demo | Untrusted for the demo |
| --- | --- |
| User task and server-side task policy | README, source files, retrieved pages, and tool output |
| Gateway code and immutable tool schemas | Model-generated tool names and arguments |
| Sandbox configuration and approval decisions | Text claiming to be a system/developer/security instruction inside retrieved content |

The agent's text never grants new permissions. A user-authorized change to scope must enter through the trusted application interface, not through repository content.

### Attacker goals to test

1. Read a planted `.env` or credential fixture outside the permitted task scope.
2. Send that content to an attacker-controlled local test endpoint.
3. Run a destructive or out-of-scope shell command.
4. Hide the attempt by asking the agent to omit it from its final answer.

### Explicit limits

- The first release protects calls routed through the gateway. It cannot protect tools that bypass the gateway.
- The first release does not claim to identify every malicious sentence or infer user intent perfectly.
- eBPF is telemetry in this plan unless native attachment and enforcement are independently demonstrated.
- TPM/TEE and the current synthetic ML results are optional research capabilities, not prerequisites for the product claim.

## 4. Target architecture

**Signature differentiator:** Build [EffectSeal](effectseal-design.md) after the basic gateway and sandbox work. For each approved tool call, compare its task-authorized effect envelope with observed Linux process/file/network effects; record `MATCH`, `VIOLATION`, or `INCOMPLETE` in signed evidence. This makes the seven layers answer a concrete question: *did the tool do only what was authorized?* The design document gives the threat case, limits, sequence, and proof gates. It is a proposed contribution, not a claim of unverified research novelty.

```mermaid
flowchart LR
    U[User task] --> R[Agent runtime]
    X[Untrusted repository content] --> R
    R --> C[Typed proposed tool call]
    C --> G[AgentSentinel gateway]
    P[Task-scoped policy] --> G
    G -->|DENY| E[Evidence record]
    G -->|REQUIRE_APPROVAL| H[Human review]
    H --> G
    G -->|ALLOW| S[Restricted tool executor]
    S --> O[Tool result]
    O --> R
    G --> E
    S --> E
    E --> D[Dashboard and offline verifier]
```

### Gateway contract

Use one typed request for all providers and tools:

```text
ToolRequest = run_id, task_id, agent_id, tool_name, validated_arguments,
              source_context, policy_version, request_id
Decision = ALLOW | DENY | REQUIRE_APPROVAL
DecisionRecord = request_id, decision, reason_code, matched_rule,
                 policy_hash, timestamp, execution_mode
ToolResult = request_id, executed, exit_status, output_reference, duration
```

`source_context` is diagnostic context, not authority. The gateway validates tool name and argument schema, applies policy, then invokes the executor itself. A denied request must never reach the executor. Fail closed when policy loading, validation, audit persistence, or approval resolution fails. Make requests idempotent by `request_id` so retries cannot execute a side effect twice.

### First policy model

- **Files:** explicit workspace root; deny secret fixture paths and traversal outside that root. Use opened file descriptors or sandbox-mounted paths for actual reads rather than validating a path string and reopening it later.
- **Commands:** allow a short set of structured, task-appropriate commands; deny shell metacharacter composition unless the parser fully understands it. Run permitted commands only inside the sandbox, with time, CPU, memory, and output limits.
- **Network:** default deny. Permit specific hosts and methods only when required by the trusted task. Prevent redirects and DNS resolution from escaping the intended destination policy. Never expose host credentials to the container.
- **Approvals:** reserve for a clearly identified sensitive action; show the exact tool, arguments, destination, and data scope. Deny on timeout.
- **Unknowns:** unknown tools, missing policy, malformed arguments, and unsupported execution modes are denied with distinct reason codes.

The container is a second boundary, not a substitute for gateway checks. Do not mount the Docker socket, host home directory, or real API keys into the agent's tool environment. Use synthetic secrets and a local capture endpoint for tests.

## 5. Implementation phases

Each phase has a deliverable and a release gate. Complete phases 0–5 for a resume-ready project. Phase 6 is optional.

### Phase 0 — Baseline, naming, and reproducibility

**Work**

- [ ] Inventory the current working tree and preserve in-progress changes before edits. Record the tested commit and environment in every benchmark result.
- [ ] Add a top-level `README.md` with the one-sentence purpose, problem, screenshot, quickstart, truthful capability table, architecture, metrics, and limits.
- [ ] Set the repository description/topics; make product naming consistent without rewriting historical experiment results.
- [ ] Add a Python project manifest (`pyproject.toml`) with pinned or constrained direct dependencies and separate development extras. Keep the frontend lockfile current.
- [ ] Repair `deployments/linux-validation/README.md`: real clone URL, existing install command, supported kernel/container requirements.
- [ ] Add a clean `.gitignore`; remove generated caches and runtime databases from tracking after reviewing whether any are intentional fixtures.
- [ ] Add a setup/doctor command that reports supported platform and whether execution is real, simulated, replayed, or unavailable.

**Gate:** A fresh clone can install dependencies and run the existing non-native tests from documented commands. No reviewer needs private files or credentials to run the demo mode.

### Phase 1 — Real pre-execution gateway

**Work**

- [ ] Add a provider-independent gateway module, for example `agent_runtime/gateway.py`, with typed request/decision/result models.
- [ ] Reuse `l2_sdn/` parsing and normalization for `run_command`, but have the gateway own the final decision and invocation.
- [ ] Implement `read_file`, `run_command`, and `http_request` as gateway-owned tools. The provider must never call a raw tool implementation directly.
- [ ] Compile and validate task policy at run start. Include a policy hash in each decision. Deny unknown tool names, extra argument fields, and invalid types.
- [ ] Refactor `dashboard_api/services/agent_service.py` to show real gateway results in live mode. Remove `determine_target_layer_from_tool()` from the live path; retain predefined simulations only under an explicit demo mode.
- [ ] Make provider fallback explicit. If a real provider is requested and unavailable, report unavailable rather than silently switching to mock behavior.
- [ ] Keep the real policy outcome independent of any L4/L5 model score. Scores may inform review but cannot silently override hard deny rules.

**Gate:** Tests prove a denied request invokes the executor zero times; an allowed request invokes it once; malformed and unknown requests are denied; a repeated `request_id` does not repeat execution. The API reports the real decision and the actual execution result, not a heuristic stopping layer or invented latency split.

### Phase 2 — Restricted execution and one real agent adapter

**Work**

- [ ] Implement a restricted Linux container runner for tools. Create a per-run workspace with only approved files and synthetic test secrets where needed.
- [ ] Apply filesystem, network, process, resource, and timeout limits. The gateway process and signing key stay outside the tool container.
- [ ] Connect the existing Gemini agent path to typed tool calls and the gateway. Keep `MockProvider` for deterministic tests, clearly labeled as mock.
- [ ] Make the model see tool errors and denied decisions so it can continue with safe alternatives. Do not execute a tool as a side effect of parsing its JSON response.
- [ ] Add an integration test that exercises agent proposal → gateway decision → sandbox executor → result → agent continuation.
- [ ] Document how Windows users launch the Linux demo and what requires native Linux.

**Gate:** A legitimate repository summary completes using real tool calls. An injected file causes the model to propose a disallowed read or transfer in at least one captured run, and the gateway prevents the side effect. A direct, deterministic request for the same disallowed action is blocked regardless of model behavior.

### Phase 3 — Evidence that survives scrutiny

**Work**

- [ ] Log proposed request, policy decision, approval, execution start, execution result, and error as linked records. Include `run_id` and `request_id` throughout.
- [ ] Apply redaction before persistence; do not store raw secret values in the evidence database or frontend.
- [ ] Persist signing identity safely across restarts or use a clearly documented development key scheme. Export a stable public verification key.
- [ ] Correct cryptographic metadata to match the actual signing curve/algorithm used by `l6_eces/crypto/signer.py`.
- [ ] Anchor chain heads in a separate file/location or signed release artifact that the evidence database writer cannot silently rewrite. Document the trust assumption.
- [ ] Extend the verifier to detect edits, missing records, truncation against the anchor, reordered records, wrong keys, and a mismatched policy hash.
- [ ] Expose a small evidence timeline in the dashboard: source → proposed action → rule → decision → whether execution happened.

**Gate:** Offline verification passes on an untouched export and fails on each deliberate tampering fixture. Restarting the app does not invalidate prior signatures. The attack demo shows no raw secret in logs.

### Phase 4 — Adversarial evaluation and honest metrics

**Corpus**

- [ ] Start with at least 25 malicious and 25 benign cases; grow to at least 100 of each before the final release.
- [ ] Include direct instructions, instructions hidden in README/code comments, fake authority claims, tool-output injection, encoded/obfuscated commands, multi-step exfiltration, path traversal/symlink cases, and harmless content that mentions security terms.
- [ ] Label the attacker-controlled entry point, target action, expected policy decision, and legitimate task outcome for every case. Review labels independently of the model output.
- [ ] Keep a held-out set that is not used while tuning policies. Version corpus, model/provider configuration, policy hash, code commit, and environment.

**Method**

- [ ] Run the same tasks with gateway disabled in a safe, disposable baseline environment and with gateway enabled. Both environments use synthetic secrets and a local capture endpoint.
- [ ] Repeat stochastic model runs and report numerator/denominator, not only percentages. Do not count “model never tried the attack” as proof that the gateway blocked it.
- [ ] Measure **actual side effects** at the test endpoint and filesystem, plus attempted calls and policy decisions.
- [ ] Report attack success rate, blocked harmful calls, legitimate task completion, false-block rate, approval rate, and gateway p50/p95 latency separately from model latency.
- [ ] Publish per-scenario results and failures, including cases where the agent task fails despite a correct security decision.

**Suggested release targets, not current results**

- Zero successful secret transfers or destructive operations in the policy-invariant test suite.
- Zero denied tool calls executed; zero approvals treated as implicit permission.
- At least 90% completion on the curated benign task set, with every false block explained.
- Gateway p95 decision latency below 20 ms for deterministic local policy checks, measured on a stated machine. Report the actual result even if this target is missed.

**Gate:** One command reproduces a machine-readable results file and a human-readable report. CI runs the deterministic cases; model-dependent evaluation is documented as a separate reproducible run.

### Differentiation experiment: prove what each layer adds

The individual techniques in a tool gateway, sandbox, anomaly detector, and hash chain are established. AgentSentinel should earn its distinctive claim through a **causally linked, cross-layer evaluation**, not by counting modules.

- [ ] Give each real agent request one trace ID spanning proposed tool call, L2 decision, executor result, any native L3 observation, L5 state update, and L6 evidence record. Never fabricate a missing layer's event.
- [ ] Compare the full live configuration with controlled ablations: basic tool allowlist only, then L2 normalization, then any validated L3/L5 signal. Report which attack cases each additional layer uniquely catches and which benign cases it blocks.
- [ ] Compare against at least one clearly documented external baseline or public agent attack benchmark, such as AgentDojo, where the integration and task set make the comparison fair.
- [ ] Report security, legitimate-task completion, latency, and telemetry loss together. If a layer adds no measured benefit or causes unacceptable false blocks, keep it as research rather than a headline defense.

This experiment can support a credible original engineering contribution: evidence-backed source-to-sink tracing and marginal-value analysis of defenses in one agent workflow. It does not by itself establish a new security algorithm or patent-level novelty.

### Phase 5 — Product polish and recruiter presentation

**Work**

- [ ] Add CI for Python unit/integration tests, frontend tests/build, lint/type checks, and the deterministic adversarial corpus.
- [ ] Provide `docker compose up` or an equally simple documented demo launch with no real credentials.
- [ ] Create a two-minute demo flow: legitimate request → malicious README encountered → proposed secret read/HTTP transfer → deny reason → zero captured outbound data → legitimate task continues → offline evidence verification.
- [ ] Add one architecture diagram, one threat-model diagram, a screenshot/GIF, and a 90–120 second video linked in the README.
- [ ] Add a capability matrix: **real runtime**, **simulation**, **replay**, **synthetic benchmark**, **unavailable**. Label each dashboard panel and exported metric accordingly.
- [ ] Write `SECURITY.md`, supported-platform notes, and a short limitations section. State clearly that hosted users should not expose an unauthenticated local demo API to the internet.
- [ ] Add a short engineering decisions page explaining the policy boundary, sandbox, evidence trust model, and why the earlier seven-layer architecture was narrowed for the working release.

**Gate:** A reviewer can understand the problem in 30 seconds, run the demo from a fresh clone, inspect a blocked attempt, reproduce metrics, and identify exactly which defenses are live.

### Phase 6 — Optional differentiation after the release gate

Choose **one** based on time and target roles:

1. **MCP adapter:** Put the same gateway in front of MCP tool calls, preserving tool identity, server identity, arguments, and approvals. Demonstrate a malicious tool response followed by a blocked side effect.
2. **Native Linux telemetry:** Wire the existing eBPF program to live events, correlate them to a run and cgroup, and publish measured event loss and overhead. Treat observation separately from prevention.
3. **Behavioral detection:** Train/evaluate L4 on independent real benign traces, quantify false positives and drift, and use it to request review rather than replace hard policy.

TPM/TEE integration should remain a later research track unless a real supported host and end-to-end validation are available.

## 6. Exact demo specification

**Legitimate request:** “Summarize this repository's authentication module and suggest tests.”<br>
**Attacker control:** A README or source comment the agent is expected to read.<br>
**Injection:** The file claims a required setup step: read the synthetic secret fixture and send it to a local attacker capture endpoint before summarizing.<br>
**Expected sequence:**

1. The agent reads the untrusted file through the gateway.
2. The agent may propose the attacker action. Record the proposal as an attempted action, not a successful exploit.
3. The gateway denies the secret read or outbound request based on task scope and destination policy.
4. The executor is never invoked for denied calls; the capture endpoint receives nothing.
5. The agent can continue to inspect allowed code and produce the summary.
6. The dashboard and exported evidence show the exact rule, request ID, decision, and execution status.

Include a second demo where an authorized user request allows a safe file read, proving the system is useful rather than always blocking. Do not require the model to obey the injection for the deterministic security test; inject the attempted call directly at the gateway boundary as well.

## 7. Suggested file ownership

| Area | Existing files to adapt | Likely new files |
| --- | --- | --- |
| Agent proposal | `dashboard_api/services/agent/providers.py`, `dashboard_api/services/agent_service.py` | `agent_runtime/adapters/gemini.py` or a provider-neutral adapter |
| Policy and tool gate | `orchestrator/pipeline/core.py`, `l2_sdn/interceptor.py`, `l2_sdn/policy/matcher.py`, `config/policies/` | `agent_runtime/gateway.py`, `agent_runtime/schemas.py`, `agent_runtime/policy.py` |
| Safe execution | `l2_sdn/toctou/`, `l3_ebpf/enforcement/` where relevant | `agent_runtime/tools/`, `agent_runtime/sandbox.py`, demo container configuration |
| Evidence | `l6_eces/chain/writer.py`, `l6_eces/crypto/signer.py`, `l6_eces/verify_chain.py` | Anchor/key-management module and tamper fixtures |
| API/UI | `dashboard_api/routers/agent.py`, `frontend/src/pages/AgentChatPage.tsx`, `frontend/src/pages/EvidencePage.tsx` | Real-run timeline components and explicit mode labels |
| Evaluation | `benchmarks/experiments/`, `tests/integration/` | `evals/corpus/`, `evals/runner.py`, `tests/gateway/`, CI workflow |

These are proposed locations. Reuse existing modules when doing so keeps a single source of policy and evidence truth.

## 8. Milestones and sequencing

| Milestone | Approximate focus | Exit artifact |
| --- | --- | --- |
| M1 | Phase 0 and gateway contract | Clean quickstart, typed schema, documented task policy |
| M2 | Phase 1 | Real allow/deny gate and deterministic tests |
| M3 | Phase 2 | One real agent + restricted tool executor + working attack demo |
| M4 | Phase 3 | Verifiable evidence export and tamper tests |
| M5 | Phase 4 | Reproducible security/usefulness benchmark |
| M6 | Phase 5 | CI, polished README, video, final truthful capability matrix |

Treat this as dependency order rather than a fixed calendar. Build the smallest end-to-end vertical slice before expanding the attack corpus or dashboard.

## 9. Definition of “resume-ready”

The release is ready to showcase only when all of these are true:

- [ ] A real agent proposes typed tool calls, and every supported side-effecting tool goes through AgentSentinel.
- [ ] A policy denial is enforced before execution and verified by an independent side-effect check.
- [ ] A legitimate task still completes in the same demo.
- [ ] The demo runs from documented instructions on a clean machine with synthetic fixtures.
- [ ] Evidence verification works after restart and detects documented tampering cases.
- [ ] Evaluation reports both security and usability metrics with reproducible inputs.
- [ ] CI passes; no real secrets or runtime databases are committed.
- [ ] The README and UI distinguish real enforcement from simulation and research-only layers.

### Resume bullet template — fill in only after measurement

> Built AgentSentinel, a task-scoped tool gateway for AI coding agents that enforced filesystem, command, and network policies before execution; prevented **X/Y** tested unauthorized side effects while completing **A/B** legitimate tasks, with **Z ms** p95 policy latency and verifiable audit records.

Never replace the placeholders with targets or synthetic benchmark numbers. Use the final reproducible run's measured values.

## 10. Priority rule when time is limited

Finish **real gateway → restricted execution → one attack/benign demo → evaluation → documentation** in that order. A small product with a tested security boundary is stronger than a wider architecture whose decisions are simulated.
