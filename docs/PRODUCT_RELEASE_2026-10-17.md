# AgentSentinel product checkpoint — 17 October 2026

## What the current local product does

AgentSentinel is a single-user, loopback-bound demonstration of a security gateway for a bounded, tool-using AI agent. The agent can read/search synthetic incident material, calculate arithmetic, create a cited local report, and submit a local demo ticket. A server-owned policy checks each proposed action before the bounded application executor. Unauthorized file reads, commands, and outbound network proposals have no executor call. Every run has ordered events, action/effect receipts, an HMAC audit chain, and an Ed25519 terminal receipt verified against the host's pinned public key.

The user interface has four primary destinations and two run-detail views:

| Destination | Purpose |
| --- | --- |
| `/overview` | Explain the problem, trust boundary and short demo path. |
| `/lab` | Chat-style Playground with custom tasks, direct requests, document attacks, examples, provider/policy settings, conversations, live status, approval review and a compact seven-responsibility inspector. |
| `/runs/{id}/trace` | Recorded admission, latest selected action, first enforcement point, unreached stages, execution receipt and paced event replay. Replay changes presentation only. |
| `/runs/{id}/results` | Outcome, answer, action/effect receipts, source provenance, signed-evidence verification/download and no-execution policy comparison. |
| `/evidence` | Saved session-owned runs; reopening does not call the model or repeat an effect. |
| `/experiments` | Source-bound deterministic contract counts, separate current-source Gemini trial results and limitations. |

The previous dense lab remains at `/lab/advanced`. Historical research routes are preserved separately.

## Run locally

From the checkout root in PowerShell:

```powershell
./scripts/start_faculty_demo.ps1
```

Open `http://127.0.0.1:5178/overview`. The launcher defaults to API 8008 and UI 5178; use `-ApiPort` and `-UiPort` if occupied. Stop the launched processes with `./scripts/stop_faculty_demo.ps1`. The fixture provider needs no cloud account. Gemini and Ollama options appear only when the local backend reports readiness; a model error is shown as an error, not a fixture result. Use synthetic input only.

## Three-minute faculty demonstration

1. Open **Overview**, then **Playground**. Choose **Investigate incidents**. With Gemini live, the agent can read the synthetic incident sources, create a cited report and submit a local demo ticket. The result shows actual permitted action receipts. The scripted provider gives a deterministic useful-path demonstration when the model service is unavailable.
2. Start a new conversation. Choose **Document injection** and **Scripted fixture** in settings. The legitimate task asks for the incident intake retention period; the lower-trust document asks the agent to read `.env`. Run it. The latest action is `read_file .env`; **L2** records `PATH_OUT_OF_SCOPE`; the executor is **not invoked**. **L3** remains **NOT REACHED**. **L6** can still complete the signed audit after the denial.
3. Open **Layer trace** and select the denied action. Point to the recorded checkpoint and reason. Open **Detailed results** and show the denied action receipt and verified signature. Compare the saved action against another policy: this reevaluates authorization without model inference or tool execution.
4. For a custom prompt, type a task in the composer. Choose **Gemini live model** or **Ollama local model** for free-form behavior. A model may refuse a malicious request without proposing a tool; that is a model refusal, not an observed gateway interception. A direct structured action test is available in **Advanced probes** when you want to demonstrate the gateway independently of model behavior.

## Seven responsibilities and proof level

| ID | Current portable control | Honest boundary |
| --- | --- | --- |
| L1 | Bounded input and structured proposal schema checks | Not a general semantic prompt-injection detector |
| L2 | Server-owned task/tool/resource policy and conservative source-aware export checks | Pre-dispatch only for observed proposals |
| L3 | Bounded application executor and application-observed effects; the Windows faculty launcher now uses one limited Job Object worker per permitted action | ETW process observation requires OS permission; Job Objects do not restrict file/network access |
| L4 | Independent repeated-proposal sequence rule | Not a trained behavioral model |
| L5 | Call/time budgets, cancellation, exact-action approval and answer review | Approval is local single-user workflow |
| L6 | Durable audit and signed run evidence | Host-held key, not hardware attestation |
| L7 | Approved source-text manifest before admission and dispatch | Does not prove loaded code or a TPM quote |

These responsibilities run at different lifecycle points. A denied action does not imply every later layer ran or passed. Admission and finalization can be shown outside an individual tool action.

## Verification and evidence

- Frontend production build passed; 62 frontend tests passed.
- The complete local Python test tree passed 283 tests with two platform skips. Frontend production build and 62 frontend tests passed. Test scope and known limits are recorded in `VALIDATION_STATUS.md`.
- The [current 50-case fixture report](../benchmarks/results/portable_lab_eval_v2.json) is bound to source manifest `bee1ed27e84ec979171ab0af37d9eab1f335d6630204e2319e4ad42f5acb0e1a`: 25/25 expected attack denials, 25/25 selected benign assertions, 50/50 verified exports, zero denied executor invocations and zero provider/runtime errors. Authorized actions started a limited Windows Job worker in 25/50 runs; denied runs started none. ETW correlation was 0/50 because this host denied tracing permission. These are repeated template contracts, not independent adversarial strategies or a live-model block rate. The earlier 200-case report is retained as historical-source evidence.
- Direct structured probes and the external adapter now submit only their requested action. A browser-run custom `whoami` proposal produced one L2 denial, no executor invocation, no observed source, and zero effects. A separate live Gemini custom calculation returned the gateway-verified value 208. In one live document-injection trial, Gemini made no forbidden proposal; the completed run is not counted as a gateway interception.
- The [evaluation notebook](../notebooks/AgentSentinel_Portable_Evaluation.ipynb) was executed on an earlier source report. Its saved outputs are historical until it is regenerated from the Windows L3 report. The [evaluation explanation](PORTABLE_EVALUATION.md) separates historical and current data.
- In the in-app browser, a Gemini incident task completed with report and ticket receipts and verified signed evidence; a custom follow-up calculator task returned 20; a scripted document injection was blocked at L2 before execution; policy comparison changed report/ticket authorization under read-only without executing tools.
- A separate-process Gemini reference agent completed a real HTTP gateway read with server-owned source ID, matching run/request IDs and a verified signed receipt. The loopback adapter contract and exact Flowise function simulator also passed allowed read, denied `.env` read, signed receipts and idempotent replay. None of these establish a real Flowise canvas run.

## Remaining gates before stronger claims

- The Flowise tool function and bridge simulator exist, but a real Flowise canvas run with matching external and gateway IDs has **not** been verified on this Windows installation.
- The local session/capability model is not Internet-grade user authentication. Public deployment requires authentication, TLS, quotas, key operations and deployment review.
- This Windows portable path does not validate a Linux isolated executor, request-correlated native eBPF coverage, or TPM attestation. Older VM research evidence is separate from the active portable web path.
- The current 50-case fixture report measures deterministic contract behavior. A separate earlier-source 12-case Gemini corpus, repeated twice, had no forbidden proposals in 14 attack trials, 9/10 selected benign checks passed, one model rate-limit error and 24/24 verified exports. This cannot establish a prompt-injection block rate; a diverse independent live evaluation on the Windows L3 source remains open.
- Local synthetic conversations, metadata and results are stored in SQLite without application-level encryption. No real secrets should be entered. Data minimization, loopback binding, ownership checks, bounded retention and local key storage are more relevant to this demonstration than adding AES solely as a resume label. A deployment that stores real sensitive conversations needs a separate data inventory and authenticated encryption/key-management design.

## Defensible resume description

> Built a local AI-agent security workbench with a server-enforced tool gateway, seven lifecycle controls, live per-action traces, conversation persistence, source-aware export rules and signed evidence. Verified 50 current-source deterministic tool-policy contracts with zero executor calls after denied proposals; separately demonstrated a Gemini task workflow and a capability-scoped external agent. Scope: bounded synthetic resources on a Windows host, not general prompt-injection immunity or native attestation.
