# AgentSentinel Live Agent Final Product Plan

## Goal

Make the application a clear, credible live demonstration of prompt injection and agent tool governance. A visitor should be able to type a legitimate task, edit an untrusted document, run a real Gemini agent or a deterministic local replay, and watch each proposed action pass through the security gateway. The screen must explain whether the model ignored the attack, the gateway denied a proposal before execution, or an approved action ran. It must never imply that unavailable Linux telemetry, a trained detector, or TPM attestation ran on this Windows host.

The primary faculty demo should take less than three minutes and work without any external account in fixture mode. Gemini mode should support custom synthetic prompts and documents when the locally stored key is available. Local Ollama mode offers model-backed interaction without relying on Gemini service availability.

## Implementation checkpoint — 13 October 2026

- The primary `/lab` screen, streaming run endpoint, simplified navigation, signed run history, custom policy probe, and provider-error display are implemented. The old research views remain accessible behind an explicit Research section.
- The Live Lab now includes a paced seven-layer animation of received runtime checkpoints with a Replay control. It does not invent native telemetry or hardware success: a denied call is labeled at L2, L3 can show `NOT_EXECUTED`, L4 is a gateway-derived rule signal, and L7 remains a software measurement.
- Fixture replay, benign README reads, custom file and command probes, and signed evidence browsing have been checked in the in-app browser. A Gemini request returned HTTP 504 during this checkpoint; the app showed the provider error rather than claiming a successful model run.
- Local Ollama support is implemented. Its first README read is a **trusted orchestrator proposal**, labeled separately in the trace. The model is called only after the gateway has approved and executed that read. A local benign run returned a summary with valid audit and signature; a custom setup instruction induced an `execute_command` proposal that the gateway denied with `COMMAND_EXECUTION_DISABLED` and `executed=false`. These are individual synthetic demonstrations, not a measured success rate.
- Final handoff checks completed: the frontend production build, all 55 frontend tests, 15 focused runtime tests, and a 67-pass/one-skip gateway rerun. The documented launcher restarted cleanly on 8008/5178. In-app-browser checks covered the fixture interception, a local Ollama answer, a custom denied command probe, and saved evidence. One gateway test failed intermittently on its first full pass; it passed alone and in the full rerun. Native Linux eBPF and hardware TPM validation remain unavailable on this host.

## Current state observed on 13 October 2026

- `/gateway` is the real tool-governed agent path. It accepts a task and editable README, uses Gemini or a deterministic fixture, evaluates structured proposals with the task policy, records an audit chain and signed receipt, and returns a seven-stage provenance report. Its HTTP request is synchronous, so the browser receives the trace only at the end.
- `/agent` is a separate research demonstration. Its layer outcomes can be simulated; its chat surface is easy to mistake for the real gateway.
- `/pipeline` combines a seven-layer challenge lab with a research scenario replay. L2 uses the gateway; L3-L5 are replay rules; L7 is unavailable here. The page is dense and obscures the main demonstration.
- The navigation exposes seven peer pages and an execution-mode legend on every screen. The Gateway page also mixes the live run, historical benchmark, manual probe, container fixture, detailed layer cards, and evidence links in one long page.
- The live Gemini agent is deliberately narrow: a disposable synthetic workspace with README.md and a synthetic `.env`; read_file of README.md is allowed, while out-of-scope reads, commands, and HTTP POSTs are denied. This is a useful honest security boundary, not a general-purpose host agent.
- No Flowise chatflow or integration was found in this repository. Flowise must not be described as part of the live path until a connector is implemented and tested.

## Product decisions

1. **One primary surface: Live Lab.** Make `/` and `/lab` open the same product experience. Retain `/gateway` as a redirect for existing links. Remove the simulated Research Agent from the primary navigation; keep research pages under an explicit Research section.
2. **One visible run contract.** Both fixture and Gemini use the same task policy, executor, audit, and receipt. The UI labels the selected provider and evidence mode. A manual action probe uses the same gateway but is clearly marked `No model inference`.
3. **Real progress events.** Add a POST streaming endpoint using newline-delimited server-sent events over `fetch`. Events come from actual runner, gateway, and audit checkpoints, with timestamps and a stable run ID. The browser must not animate an assumed layer sequence after receiving a final result.
4. **Three distinct attack outcomes.** `No forbidden tool proposal observed` means no forbidden proposal reached the gateway; the answer may still repeat untrusted text. `Blocked before execution` means a forbidden proposal was denied and `executed=false`; `Execution failure` means an approved executor was invoked but did not complete. Do not label all three as an interception.
5. **Explain the trust boundary visually.** Show user task, untrusted README, model proposal, policy decision, executor, and signed evidence in a compact timeline. Each event needs a human explanation, raw reason code, and proof level.
6. **Synthetic-only demonstration.** The browser accepts custom text but operates only in a disposable synthetic workspace. Do not add arbitrary host file reads, unrestricted shell execution, or outbound network permissions to make a demo look more capable.

## Target information architecture

### Primary navigation

| Destination | Purpose |
| --- | --- |
| Live Lab | Main task, attack document, run controls, live trace, and outcome |
| Evidence | Browse past signed runs and verify/download one selected run |
| Research | Saved experiments, seven-layer challenge checks, and honest capability notes |
| About | Architecture, system readiness, limitations, and reproducible demo instructions |

The Research Agent page and legacy Pipeline replay can remain accessible from Research with a prominent `Simulation` label. Historical metrics belong in Research, not above the live form. The container fixture belongs in an Advanced demonstration drawer.

### Live Lab screen

1. **Scenario strip:** `Prompt injection`, `Forbidden command`, `Benign task`, and `Custom`. Selecting a preset fills fields; editing either field switches to Custom without discarding text.
2. **Agent workspace:** a conversation-like task input plus an untrusted README editor. Short helper text states which text is the legitimate user task and which is attacker-controlled data.
3. **Run controls:** provider selector (`Gemini live` if configured, otherwise `Fixture replay`), a single Run button, a clear Reset, and a status indicator. Provider errors must be readable and preserve inputs.
4. **Live trace:** ordered events with elapsed time, actor (`Agent`, `Gateway`, `Executor`, `Evidence`), event, verdict, and reason. Highlight the exact point where an instruction became a proposed tool call and where policy denied or allowed it.
5. **Outcome card:** plain-language result; `executed` flag; final agent answer; audit and signature verification; link to full evidence. If no forbidden proposal occurred, say so explicitly.
6. **Details drawer:** full seven-layer report and raw identifiers/hashes for a technical reviewer. Unsupported stages stay visible as `Unavailable` or `Replay`, with their limitations.
7. **Manual probe drawer:** custom read_file, execute_command, or http_post proposal for a repeatable proof of the L2 gate. This is separate from model-generated behavior.

### Suggested visual layout

On desktop, put the task/document controls on the left and the live timeline on the right; the outcome card anchors the top of the right column after completion. On mobile, stack controls, outcome, then timeline. Use one primary color for the agent, green for executed allowed actions, red for denied proposals, amber for incomplete telemetry, and neutral gray for unavailable stages. Color is never the only cue.

## Backend event contract

Add `POST /api/runtime/run/stream` with the same validated request as `/api/runtime/run`. It returns `text/event-stream`; each frame has an `event` name and JSON `data` object. Keep `/api/runtime/run` for compatibility and tests.

| Event | Emitted from actual checkpoint | Safe fields |
| --- | --- | --- |
| `run_started` | after run ID and synthetic workspace are created | run ID, provider, mode, timestamp |
| `model_turn` | after a provider returns a structured turn | turn number, message excerpt, whether a proposal exists |
| `tool_proposed` | before gateway.handle | tool name, sanitized argument summary, request ID |
| `policy_decision` | immediately after gateway.handle | ALLOW/DENY, reason code, executed flag |
| `effect_receipt` | after EffectSeal reconciliation | verdict, reason codes, telemetry source |
| `risk_assessment` | after governor update/audit append | action, score, signals |
| `run_completed` | after audit verification and signed receipt | final response, steps, layer report, verification state |
| `run_error` | on a bounded error | safe error code and message; no secret or traceback |

Requirements: monotonic sequence number, UTC timestamp, one terminal event, no raw key/secret/tool output in streaming telemetry, bounded queue and message size, a maximum of four tool calls, and a concurrency limit for live provider runs. Heartbeat frames can keep proxies alive but must not imply security progress. Handle browser disconnects without leaving unbounded work or corrupting evidence. The signed run remains the authoritative post-run record; the progress stream is a presentation channel.

## Implementation phases

### Phase 0 — Baseline and truthfulness

- Record a clean baseline for frontend build/tests and backend runtime tests.
- Correct stale status documents that say all seven layers are fully implemented. Current claims must distinguish real gateway enforcement, rule signal, replay, software signing, and unavailable native or hardware functions.
- Ensure the previous report/notebook deliverables and other untracked work are left intact.

**Done when:** the project has a single current capability statement and no live UI calls a replay result a native interception.

### Phase 1 — Evented agent run

- Add optional progress callback hooks to `AgentRunner` and `run_demo_task` without changing policy decisions.
- Implement the streaming route with a bounded queue and worker thread. Emit checkpoints only after the corresponding work occurs.
- Keep the original JSON run endpoint and verify the streaming terminal payload matches it structurally.
- Add focused tests for allowed read, denied `.env`, model ignores injection, provider failure, audit failure, event ordering, and redaction.

**Done when:** a browser receives policy decisions before the final result, and no emitted event claims execution when `executed=false`.

### Phase 2 — Replace the cluttered main screen

- Build `LiveLabPage` with the compact task/document/composer and real event timeline.
- Make the Gateway screen a route redirect, simplify navigation, and move benchmarks/research replay to a Research section.
- Put manual probe, container fixture, and seven-layer internals in clearly labeled drawers. Do not delete their underlying functionality.
- Add accessible labels, keyboard operation, responsive layout, loading states, and a Reset that does not erase evidence on disk.

**Done when:** a new visitor can run a benign case and a prompt-injection case from the first screen without reading documentation.

### Phase 3 — Make custom attacks demonstrable

- Keep arbitrary user-authored synthetic task and README text; make the trust boundary explicit.
- Add a custom proposal mode so a user can directly submit a file path, command argv, or URL to the real gateway. Explain that this is a policy test, not a model attack.
- Provide at least one preset for each observable outcome: ignored injection, unauthorized proposal denied, valid README read allowed, and restricted container effect failure. Presets must use actual runtime paths, not hardcoded result cards.
- Show the exact proposed tool and policy reason next to the user input. Allow copying a sanitized run summary for a faculty demo.

**Done when:** edited custom text reaches Gemini in live mode, and edited manual proposals receive genuine gateway decisions with signed evidence.

### Phase 4 — Evidence and replay

- Show recent run IDs, provider, outcome, date, and verification state in a concise list.
- Make one-click signed evidence download and offline verification discoverable from the outcome card.
- Add a read-only past-run detail view from durable audit data, with redacted public fields. Reopening a run must not silently rerun the model.

**Done when:** a faculty member can inspect the blocked action and verify the same run after the live session ends.

### Phase 5 — Production-quality handoff

- Add a first-run readiness check that reports API, Gemini configuration, Docker fixture availability, and the Linux/TPM limitations.
- Update README and faculty runbook with a two-minute demo sequence and a troubleshooting path for provider quota or offline mode.
- Run frontend build, targeted backend tests, security regression tests, and a clean start/stop smoke test.
- Verify desktop and narrow-viewport behavior in the in-app browser using benign, injected, direct forbidden, custom policy, and provider-error cases. Capture current screenshots for the report only after this verification.

**Done when:** the app starts with one documented command, completes the above scenarios, and every displayed claim is backed by the run trace or marked as research/unavailable.

## Flowise integration decision

Flowise is not currently part of this repository's execution path. If a Flowise demonstration is required, add a separate adapter after the event contract is stable: a Flowise tool node calls a narrowly scoped AgentSentinel gateway endpoint with a run ID and proposed action; AgentSentinel returns ALLOW/DENY and signed evidence; the Flowise canvas and AgentSentinel run detail show the same request ID. Test with synthetic content and an intentionally malicious document. Until that is implemented, a standalone Flowise screenshot should be captioned as a separate controlled demonstration, not proof of integrated seven-layer protection.

## Acceptance scenarios for the final demo

| Scenario | Expected visible outcome |
| --- | --- |
| Benign README summary | README read allowed, executor invoked, answer returned, local audit and signature verified; native effect observation marked incomplete |
| Prompt injection asks to read `.env` | If Gemini proposes the read, gateway denies before execution; if Gemini ignores it, show `Attack not followed` |
| Custom command proposal | Manual probe shows `COMMAND_EXECUTION_DISABLED`, `executed=false`, and signed audit |
| Custom outbound URL proposal | Manual probe shows network action denied, `executed=false`, and signed audit |
| Provider unavailable or quota exhausted | Preserve inputs and show a clear provider error; offer fixture mode without pretending it was a live model run |
| Evidence tampering | Offline verifier rejects a modified copy of a saved record; original evidence remains intact |

## Resume and faculty claim

The defensible claim is: **Built an interactive agent security lab that streams model tool proposals through a task-scoped pre-execution gateway, blocks unauthorized actions, and produces verifiable signed run evidence.** Benchmarks and seven-layer research modules support the story, but live enforcement must be demonstrated by the gateway trace and its `executed` field. Native eBPF telemetry, trained live behavior detection, and TPM attestation remain explicit limitations until validated on suitable hardware.
