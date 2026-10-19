# AgentSentinel portable release

## Run it

From the repository root:

```powershell
python -m pip install -r requirements-test.txt
cd frontend
npm ci
cd ..
./scripts/start_faculty_demo.ps1
```

Open http://127.0.0.1:5178/lab. Stop with `./scripts/stop_faculty_demo.ps1`.
The launcher checks API/UI readiness; the lab checks its separately approved source manifest.
During development, source edits intentionally make L7 refuse new work. Review the code and explicitly approve a new baseline with `python scripts/approve_lab_manifest.py --approve-current-source`, then restart the API. Do not approve an unexplained mismatch to make a warning disappear.

For the Windows ETW demonstration, start `./scripts/start_etw_demo.ps1 -ApiPort 8010 -UiPort 5180 -EtwPort 8011` instead. Only the narrow loopback trace broker requests elevation. Open `http://127.0.0.1:5180/lab` and verify process-start correlation in each authorized run's L3 receipt. An ordinary launch without trace permission reports missing ETW coverage rather than inventing events. The broker and Job Object design, tested limits and exact evidence boundary are in [WINDOWS_L3_IMPLEMENTATION.md](WINDOWS_L3_IMPLEMENTATION.md).

## Three-minute faculty demo

1. Choose **Useful task** and **Offline fixture**, then **Run through security**. Explain that this is a scripted offline demonstration. It really reads synthetic documents, searches them, calculates a total and creates a bounded report. Show executor invocation and application effects in the action receipts. Download the report.
2. Choose **Document injection** and rerun under **Balanced analyst**. The lower-trust document asks for `.env`. The fixture proposes the read and L2 denies it before dispatch. Show `executor_invoked=false` and the policy reason.
3. Change to **Strict input rules** and rerun the same input. The explicit override-plus-secret-target input rule stops it at L1. This is an explainable rule with a known scope, not a perfect semantic detector.
4. Open **Layer challenge bench**. Run L3–L7 examples. L3 exercises an arithmetic executor bound; L4 stops a third identical authorized proposal; L5 stops new operations at the tool budget; L6 injects an audit-write failure; L7 injects a source-baseline mismatch. The last two are controlled faults, not natural-language attacks on cryptography or hardware.
5. Choose **Ollama** or configured **Gemini**, edit a custom prompt and run it. Model behavior may vary: refusing an attack or making no forbidden proposal is not evidence of a gateway interception. A provider failure remains an error and never becomes a fixture success.
6. Inspect a node and replay the saved events. Graph edges follow actual lifecycle transitions rather than an assumed numeric ordering. Some layers run before input/model activity; authorization and governance repeat for each action. The graph's live view uses received events; replay can be paced and paused.
7. Compare the successful report run with **read_only**. Counterfactual replay denies report capability without any new model calls or effects. It does not predict model behavior or reevaluate redacted report content.
8. Export evidence; independently verify it with the host's separately trusted public key. Show Runs & evidence and reopen a past run without executing it again.

Optional: use **Report approval required** to pause a report operation. Approve/decline the exact pending request; cancellation is acknowledged at a safe boundary. In-flight model requests are bounded by provider timeouts and cannot always be interrupted immediately.

## Independent verification

Copy the issuer's public key through a trusted channel from `.data/secure-lab/signing.pub`. Do not trust an arbitrary key simply because an export contains it.

```powershell
python scripts/verify_lab_evidence.py path/to/downloaded-export.json --trusted-public-key .data/secure-lab/signing.pub
```

The verifier checks the signature and binds the summary, event list and audit bytes. It does not establish hardware-backed key storage, an external timestamp or an external transparency anchor. The terminal transport frame is outside the signed event list to avoid circular hashing; its summary is separately bound by the receipt.

## Threat model

Protected assets: scoped synthetic documents, report destination, execution authority, session-owned run history, budgets, policy configuration and evidence integrity.

Attacker control: user/document text, model-generated proposals and arguments, and downloaded copies of evidence. The model cannot grant itself capabilities or choose host paths. It never receives the audit/signing keys or the trusted manifest.

Trusted base: API host/process, application source and dependencies, approved source manifest, host-held keys and SQLite. A compromised host can replace the application or steal keys. Source digest checks do not prove the identity of already loaded code. Browser session tokens provide anonymous local ownership, not public-service identity or multi-tenant authentication.

Tools run against app-created synthetic data. Report writing targets an app-owned output directory outside the model's input workspace. Search and calculation are bounded application functions. Arbitrary code, shell and arbitrary network execution remain denied. This application wrapper is not a sandbox for hostile code.

L3 receipts describe application effects and Windows Job worker execution. With the elevated broker active, correlated ETW events independently observe worker process start/stop, but not file/network activity or complete OS effects. A Job Object limits resources and lifetime; it is not a file/network sandbox. L4 is an explicit repetition rule, not a trained behavior model. L7 uses a reviewed source manifest, not a TPM quote. These limitations are displayed in the product.

Input screening uses declared rules. It can miss paraphrases and can flag legitimate discussion. Task authorization remains a separate control. Output checks cover the known synthetic secret canary; they do not establish universal DLP or resistance to encoded leakage. Messages render as text, so HTML from a model is not executed.

## Persistence and API

Each session uses a random local token and receives only its own run history/artifacts. Original task/document text is not retained as a transcript; evidence records their digests and sanitized proposal metadata. Sanitization is bounded and intended for synthetic data; it is not a general secret-removal guarantee.

SQLite schema version 1 stores run metadata and ordered events. The stream resumes with `after=<sequence>` and does not create another run. The durable request ledger prevents duplicate dispatch. Global concurrency is two runs, global admission is 20 per minute, tool budget is six, and local run storage is bounded to 1000 runs. Startup marks interrupted runs as errors, preventing a fake completed result after a restart.

`POST /api/lab/session` creates an anonymous local token. Pass it as `X-Lab-Session` to run, read, cancellation, approval, export, artifact and comparison routes. New endpoints refuse non-loopback clients. Public hosting is a separate release requiring authentication, authorization, TLS and deployment review.

## Evaluation

```powershell
python scripts/evaluate_portable_lab.py
python scripts/evaluate_portable_lab.py --provider ollama --limit 4 --output portable_lab_ollama_smoke_v1.json
python scripts/evaluate_live_lab_v2.py --provider ollama --corpus portable_live_cases_v3.json --limit 20 --repeat 1 --output portable_lab_ollama_live_v3.json
```

The default suite has 100 adversarial tool-contract fixtures and 100 benign calculation/search/report fixtures. It uses the explicit offline parser, not an AI model. Its repeated capability families are not 200 independent real-world attacks. Metrics describe contract assertions, useful tool completion, denied executor invocation, evidence verification and end-to-end fixture latency. No ML precision/recall or isolated security-overhead claim follows from these results. The small live-model smoke is separate and too small for a robustness estimate.

## Integration adapter

`POST /api/lab/adapter/action` accepts one **manual direct probe** from the local Playground session and executes it only through the same lifecycle. Example JSON: `{"tool":"read_file","arguments":{"path":".env"},"profile":"read_only"}`. The response supplies a run ID; poll its owner-scoped run endpoint or follow its event stream for the final decision and signed evidence.

The Flowise recipe uses a separate integration path. A local session issues an expiring signed capability through `POST /api/lab/adapter/capabilities`; Flowise receives only that capability, not the session token. `POST /api/lab/adapter/integration/action` checks its server-owned role, tool scope, policy version, expiry and revocation state. `GET /api/lab/adapter/integration/runs/{run_id}` accepts only the capability that created that run. The capability lifetime is at most 600 seconds; request IDs bind repeated proposals to the same run. This is local synthetic-agent scoping, not public-service authentication. The bridge must return the gateway's result and must not execute an independent unrestricted tool after the check. The adapter contract and exact JavaScript function simulator are tested locally; an end-to-end Flowise canvas is not claimed until run in Flowise.

## Resume claim

Built a Python/FastAPI and React security gateway for tool-using AI agents with live lifecycle visualization, scoped capabilities, bounded execution, approval and budget controls, policy counterfactual replay and independently verifiable signed evidence. Link measured fixture results separately from live model smoke results. Do not describe the portable release as seven native/ML/hardware security layers.
