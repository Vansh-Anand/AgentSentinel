# AgentSentinel portfolio review and UI plan

Review date: 15 October 2026. Scope: the portable lab source, API/tool/provider contracts, evaluation generator, test inventory, and the Lab and System Status screens at review time. This was a focused product/code review, not a penetration test. The recommendations below are the original plan; see [portfolio handoff](FINAL_PORTFOLIO_HANDOFF.md) for the subsequent implementation and validation boundaries.

## Assessment

The project has substantive engineering: pre-dispatch tool authorization, bounded useful operations, durable events, request-bound approval, independently verifiable signed evidence, saved replay and policy comparison. The strongest positioning is an observable security gateway for tool-using AI agents. A perfect score or general prompt-injection immunity cannot be supported by the present evidence.

The largest gaps are product coherence, realistic workflows, depth of evaluation and demonstrated integration. More layer names or decorative dashboards would not resolve them.

## Findings from the current project

1. `/system` shows the research architecture: L1 Grammar-Constrained Decoding, L2 Semantic Detection & Normalization and L7 Agent Isolation. `/lab` shows input/schema, task authorization and software integrity. The same IDs describe different controls. `SystemStatusPage.tsx` uses the older status hook instead of the portable capability contract. Publish one versioned capability registry and label research separately.
2. `SecureLabPage.tsx` gives the hero banner, presets, input source, provider, policy, explanations, graph, result, latest action, receipts and trace competing visual weight. At narrow widths the hero and navigation occupy much of the initial viewport before the prompt. Settings and diagnostic detail need progressive disclosure.
3. `SecurityGraph.tsx` positions layers in a ring ordered L7/L1/L4/L5/L2/L3/L6 and draws up to 40 historical edges. This is defensible as lifecycle ordering but hard for a first-time viewer to follow. Use per-action focus, direction arrows and a readable stage label; retain all seven responsibilities with a clear distinction between run-wide checks and action checks.
4. The offline provider recognizes explicit phrases and produces a fixed report workflow. Keep a visible Scripted demo badge and select a ready live provider for custom free-form tasks. Never silently fall back to fixtures.
5. `evaluate_portable_lab.py` generates 100 attack rows from four families repeated 25 times. Benign assertions use expected-answer substrings. This supports contract regression; it is weak evidence for diverse semantic attacks and independently verified task correctness. The newer live reports contain only four Ollama and two Gemini trials.
6. L1 is a narrow explicit input rule, L4 detects repetition, and output release checks a known synthetic canary. Their scope is legitimate but narrow. Native observation, trained anomaly detection and general DLP are not delivered by these controls.
7. The tool adapter endpoint is implemented and locally tested, but a complete external Flowise canvas has not been demonstrated. Local random session tokens and loopback restrictions do not constitute public-service user authentication.

## Target user experience

Primary navigation: Playground, Runs, Evaluation. Put connection/provider status and diagnostic settings behind a compact status control; research stays in a clearly labeled secondary area.

On desktop, show a chat-style task panel beside a compact live security inspector. Keep the prompt composer and Run button immediately visible. Start with three examples: investigate incidents, attempt a forbidden secret read, and inject a document. Move provider and policy controls into Settings, while retaining a visible current provider and permission badge.

Before a run, show one sentence explaining the task and three examples. During a run, show the agent's public message, proposed tool and a short event-driven explanation. After a run, show one verdict: completed, action blocked, approval required, cancelled or failed. Include the plain-language reason before the technical reason code.

Use a detail drawer for tool arguments, policy version, event timestamps and signature details. Use tabs for Answer, Security trace and Evidence rather than appending all sections vertically. Separate L7 admission and L6 audit from the repeated tool-action sequence; the inspector can still show the status of all seven layers.

True follow-up chat requires explicit server-side conversation state, task boundaries and session-wide budgets. A chat visual design alone must not imply that prior context is remembered. Clear/new task must reset context deliberately; prior untrusted documents retain their source labels.

### Animation specification

- Animate a packet on the edge corresponding to a received backend transition; show its tool/action ID. Do not animate invented checks.
- Give the active check a subtle pulse, fade successful checks to a quiet completion state, and show one restrained stop pulse on denial.
- Keep a short human-readable caption synchronized with the selected event, such as "Checking permission to read .env".
- On block, stop the action path and grey out unreached execution stages. Evidence finalization may still continue and must be shown separately.
- Collapse older action paths into a step list so earlier edges do not obscure the current one.
- Recorded replay supports play/pause, step forward/back, speed and a scrubber. A slower presentation mode must say Recorded replay and preserve real timestamps.
- Use short opacity/transform transitions for drawers and message arrival. Respect reduced-motion preferences; avoid permanent flashing, particles and security-score animations with no measured meaning.

## Features with the highest portfolio value

### 1. One realistic incident-triage workflow

Create an app-owned synthetic incident dataset. Let the agent search events, read incident notes, calculate counts, draft a cited incident summary and propose a local demo ticket. Place an injection in one note requesting a restricted attachment or unauthorized export. The same task must succeed on benign data and preserve useful work when the malicious action is blocked.

All new tools must execute through the gateway. A local ticket destination is an explicitly bounded app service, not arbitrary network access. Validate allowed reads, meaningful report contents, permitted ticket creation and unauthorized variants.

### 2. Provenance and information-flow policy

Assign source IDs and classifications on the server. Trace document reads into subsequent tool proposals and reports. Add a conservative rule that a run exposed to a restricted synthetic source cannot export its contents without an explicit capability/approval. Show the source and rule responsible for the decision. Labels must not be supplied by model output; paraphrase/encoding handling and overblocking need separate evaluation. This is a useful distinguishing extension, not an established novelty claim.

### 3. Reviewable approvals

Show the exact report/ticket content, destination and requested capability before approval. Bind approval to normalized arguments, content digest, request identity and expiry. Edits or retries with changed content require a new approval. This extends the existing request-ID approval and makes the UI a meaningful security control.

### 4. Evidence investigation

Promote existing policy counterfactual replay to an obvious Compare policy action. Display the first changed authorization and state that no tools were executed. Add a local evidence verification view which accepts an export and separately trusted issuer key and highlights changed content. Preserve the CLI verifier and distinguish a valid signature from independent trust in the signer.

### 5. One complete integration

Build one Flowise custom tool workflow using the existing adapter. Its tool must return the gateway execution result and have no separate unrestricted executor. Demonstrate an allowed operation and a denied operation with matching run/request IDs on both sides. Document setup and failure behavior before adding more agent frameworks.

## Evaluation and engineering gates

- Retain the 200 fixture contracts as deterministic regression evidence. Add a separate diverse live corpus with direct requests, document injection, role spoofing, encoded instructions, multi-step scope expansion and benign security discussions.
- Separate development templates from held-out test families. Repeat representative live cases and record model/version/settings, errors, refusal, unauthorized proposal, prevented execution and actual attacker-objective success separately.
- Verify benign outcomes using tool receipts and structured artifacts, not just text containing an expected number. Report useful-task success, false-positive interruption, unauthorized execution conditional on a proposal and per-family counts.
- Measure gateway overhead separately from total model latency. Compare input rules, authorization and combined defenses within an isolated synthetic harness. Report uncertainty and template dependence.
- Extend regression tests for argument mutation after approval, retry/idempotency at run creation, reconnect without duplicated effects, cancellation during pending work, artifact tampering, path normalization, concurrency and storage exhaustion. Audit coverage before adding redundant tests.
- Introduce typed backend event schemas and split the large UI component into composer, run controller, transcript, trace and evidence views. Keep one source of truth for layer names and capabilities.
- Add dependency/secret scans and artifact version/source linkage to CI; inspect existing coverage first. Add a cleanup/retention policy for the local store's 1000-run cap.
- For a public deployment, first implement real authentication, user-scoped authorization, quotas, TLS, secure provider-key storage and isolated workload design. Do not expose the current local demo by changing its bind address alone.

## Delivery order and acceptance

| Order | Change | Acceptance |
| --- | --- | --- |
| 1 | Unify architecture/status and simplify the main screen | Layer meanings match across pages; first-time visitor can find prompt, Run and outcome without opening diagnostics. |
| 2 | Event-driven motion and per-action inspector | Animation matches recorded events; early stops never fabricate downstream passes; narrow layout and reduced motion verified. |
| 3 | Realistic incident workflow and meaningful approvals | Benign task produces a checked artifact; malicious variant is blocked at the actual boundary; approval displays and binds the proposed content. |
| 4 | Provenance and policy comparison | Source labels are server-owned; changed policies are compared without effects; known information-flow cases have expected outcomes and overblocking measurements. |
| 5 | Expanded evaluation and failure tests | Results separate contracts, live model behavior and errors; repeated held-out evidence is reproducible. |
| 6 | External integration and portfolio package | Actual Flowise run verified; clean install exercised; concise README, threat model, architecture, two-minute video and versioned results delivered. |

Keep eBPF, TPM, distributed deployment and trained anomaly detection as separately validated extensions. The current host does not support claiming those capabilities as active protections.

## References checked for this review

- OWASP excessive agency: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- OWASP agentic application risks: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- NIST agent hijacking evaluation: https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations

These sources motivate task-scoped authority and stronger evaluation. They do not certify AgentSentinel or establish that its features are novel.
