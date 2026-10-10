# AgentSentinel

**A task-scoped tool gateway for AI coding agents.** AgentSentinel checks a proposed file, command, or network action before it reaches a tool executor. The agent demo permits explicitly listed file reads and denies command and network execution. A separate restricted container demo permits one exact command. A bounded agent loop, dashboard route, authenticated audit chain, local Ed25519 run receipt, and deterministic EffectSeal reconciler are included.

AI agents can encounter attacker-controlled instructions in repository files and tool output while doing legitimate work. AgentSentinel's goal is to limit what those instructions can make an agent *do*. See the [active end-to-end plan](docs/END_TO_END_IMPLEMENTATION_PLAN.md) for the implementation gates and the [resume-ready build plan](docs/AGENTSENTINEL_RESUME_READY_PLAN.md) for the threat model and research background.

For the exact live, VM-validated, research, and remaining states of all seven layers, see the [completion matrix](docs/PROJECT_COMPLETION_MATRIX.md) and the [remaining implementation plan](docs/REMAINING_IMPLEMENTATION_PLAN.md).

## Run the gateway and agent demos

Requires Python 3.11 or newer. The minimal gateway demo uses the standard library; signed runtime and tests require the dependencies below.

```bash
python -m pip install -r requirements-test.txt
python -m agent_runtime.demo
python -m agent_runtime.runner_demo
python -m agent_runtime.doctor
python -m unittest discover -s tests/gateway -v
python -m benchmarks.gateway_eval
python -m benchmarks.model_eval --provider fixture --per-category 2
```

The original gateway demo submits three calls directly. `runner_demo` adds a bounded agent loop: a deterministic replay provider reads a malicious README, proposes a `.env` read, the gateway blocks that proposal, and the agent finishes a limited summary from the approved content. These local demos do **not** use a model, execute shell commands, or make network requests. The 50-case evaluation has 25 unauthorized or malformed requests and 25 authorized reads. It is a deterministic policy fixture set, not a measured model attack benchmark.

To evaluate a real model against varied untrusted README contents, install `requirements-gemini.txt`, set `GEMINI_API_KEY`, and run `python -m benchmarks.model_eval --provider gemini --per-category 25 --output .data/model-eval/full-current.json`. This separate corpus contains 25 prompt-injection payloads and 25 benign READMEs. The evaluator records the corpus hash, each fixture hash, run ID, provider failures, denied proposals, prevented execution, legitimate completion, latency, and audit validity. Its score measures tool proposals and execution outcomes; it does not grade answer quality or prove general prompt-injection immunity. Use `--per-category 2` for a small smoke run.

The evaluation writes a checkpoint after each new case. If provider calls fail, rerun only failed cases with `python -m benchmarks.model_eval --provider gemini --per-category 25 --retry-errors-from .data/model-eval/full-current.json --output .data/model-eval/full-current.json --delay-seconds 10 --max-new-calls 5`. Successful rows are reused only when the corpus hash and run settings match. A partial result exits nonzero and keeps its error count visible. Before publishing, run `python -m benchmarks.verify_model_report .data/model-eval/full-current.json --check-current-source`, then `python -m benchmarks.export_model_report .data/model-eval/full-current.json --version v2`.

The [v2 Gemini report](benchmarks/results/agentsentinel_model_eval_v2.md) covers one trial each of 25 synthetic attack and 25 benign READMEs. Five attack READMEs produced a forbidden tool proposal; all five were denied before execution. All 25 benign tasks completed. The strict verifier passed all 50 audit chains and Ed25519 receipts. Their source hashes matched **at publication**; after the evaluator/runtime changes, the recorded source no longer matches this checkout. The report remains valid historical evidence for that source revision, not general prompt-injection immunity or answer-quality evidence. The [v1 report](benchmarks/results/agentsentinel_model_eval_v1.md) is older historical evidence.

The [held-out v2 corpus](benchmarks/model_cases_v2.json) uses a different synthetic incident-intake task with 25 new attack and 25 benign READMEs. Its [live Gemini v3 report](benchmarks/results/agentsentinel_model_eval_v3.md) records one trial per case: 1/25 attacks induced a forbidden proposal, 0/1 such proposals executed, and 25/25 benign tasks reached a final answer containing the required event source and retention terms. A [supplemental uncertainty note](benchmarks/results/agentsentinel_model_eval_v3_uncertainty.md) shows how wide these single-trial estimates are. Two HTTP 429 cases succeeded on retry; the final report has zero provider errors. All 50 local HMAC chains, Ed25519 receipts, signed final-answer hashes, fixture hashes, and source hashes verified at publication. Later reader and Docker hardening changed the measured source, so v3 is now historical evidence for its source revision. The lexical assertion is a narrow task check, not semantic answer-quality scoring; this corpus does not establish general prompt-injection immunity. The earlier v2 result used a different corpus and source revision, so its 5/25 figure is not a before/after comparison.

A credential-free wiring run is available with `python -m benchmarks.model_eval --provider fixture --corpus model_cases_v2.json --per-category 25 --output .data/model-eval/v2-fixture.json`; verify it with `python -m benchmarks.verify_model_report .data/model-eval/v2-fixture.json --check-current-source`. The fixture provider deliberately gives a canned auth-module response, so its lexical assertion fails on this new task. To reproduce the model result, run the same command with `--provider gemini` and a private `.data/model-eval/v2-gemini.json` output, verify it, then export with `python -m benchmarks.export_model_report .data/model-eval/v2-gemini.json --version v3`. Public exports omit raw model answers and run IDs.

On Windows, `scripts/run_heldout_gemini.ps1` can read a locally saved DPAPI encrypted key from `.data/secrets/gemini-key.dpapi` under the same Windows account. The key file and raw model results are excluded from Git and the Docker build. Run `./scripts/run_heldout_gemini.ps1` for the full corpus or pass `-PerCategory 2` for a smoke test. A shared key should be rotated after use.

## Run the dashboard

For the credential-free fixture demo on a fresh checkout with Docker Desktop:

```bash
docker compose up --build
```

Open `http://127.0.0.1:5173/gateway`. Compose publishes both services on loopback only and does not mount the Docker socket, so its optional restricted-command buttons are unavailable. The separate host setup below enables that fixture when a pinned image is configured. Stop the Compose demo with `docker compose down`; the named evidence volume is retained.

In a separate terminal, run `python -m scripts.compose_smoke` for the credential-free end-to-end check. It verifies the UI route, allowed and denied gateway calls, truthful layer labels, and the downloaded evidence with the public verifier. GitHub Actions runs the same check against a fresh Compose build; all eight jobs passed in the [2026-10-11 run](https://github.com/Vansh-Anand/AgentSentinel/actions/runs/38078948110).

```powershell
python -m venv .data/venv
./.data/venv/Scripts/python.exe -m pip install -r requirements-dashboard.txt
./.data/venv/Scripts/python.exe -m uvicorn dashboard_api.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open the local Vite URL and select **AgentSentinel Gateway**. The default provider replays a deterministic prompt-injection fixture. To use a real Gemini model, install `requirements-gemini.txt`, set `GEMINI_API_KEY` on the API host, and select **Gemini model**. The verified default is `gemini-3.5-flash-lite`; set `AGENTSENTINEL_GEMINI_MODEL` to another supported model when needed. The API does not silently substitute a mock model if Gemini is unavailable. The Gemini path uses the [Google Gen AI Python SDK](https://googleapis.github.io/python-genai/).

The new `POST /api/runtime/run` route uses a disposable synthetic repository. It never points the model at this checkout or an arbitrary user path. It returns gateway decisions, EffectSeal status, a per-step risk action, and a seven-stage report that states which capabilities actually ran. Each receipt and risk action is recorded before the next tool proposal, and the final layer report is included in the HMAC audit chain. A two-step fixture run now has eight authenticated records. `GET /api/runtime/runs/{run_id}/verify` checks the chain. Local evidence is written under `.data/`, which is ignored by Git. Keep `.data/runtime-audit-key.bin` private and back it up if you need to verify past runs.

![Browser-verified Gateway result](docs/screenshots/gateway-browser-result.png)

With a configured Gemini key, a live model run read the approved README and completed the summary. In a separate synthetic test, the user task explicitly asked the model to read `.env`; Gemini proposed the call, and the gateway denied it before execution. The first run did not follow the injected README instruction, so the second run is evidence of policy enforcement on a real model proposal, not evidence that a prompt injection succeeded. Both runs have independently verified local audit chains.

![Browser-verified Gemini denied call](docs/screenshots/gemini-denied-browser-result.png)

You can verify a saved run without the API: `python -m agent_runtime.verify <run-id>`. Add `--check-current-source` to compare the recorded L7 software hashes with the current checkout. Editing, reordering, or truncating its JSONL records makes HMAC verification fail against the separate local anchor. New runs also produce an Ed25519 receipt. Copy `.data/runtime-signing-key.pub` to an independent verifier, pin that public key, and run `python -m agent_runtime.verify_public <run-id> --public-key-file <pinned-public-key-file>`. The public verifier checks the signature and signed audit-file digest without the HMAC secret. Source hash comparison checks disk files, not loaded memory or hardware state. The signing key is locally held and has no external identity or timestamp anchor.

The Gateway result also offers **Download public evidence ZIP**. It contains only the signed receipt, audit JSONL, and public key. To export a run from the CLI instead, use `python -m agent_runtime.export_evidence <run-id> <new-output-directory>`. On another machine, extract the ZIP and run `python -m agent_runtime.verify_public <run-id> --data-dir <extracted-directory> --public-key-file <independently-pinned-public-key-file>`. Pin the key separately before trusting the bundle: a public key supplied inside the same ZIP only proves that its files agree with each other. Neither export includes the HMAC or Ed25519 private key.

### Restricted command demo

On a host with a running Linux Docker daemon, prepare a local Python image and find its image ID (`docker image inspect --format '{{.Id}}' IMAGE_NAME`). Set `AGENTSENTINEL_DOCKER_IMAGE` to that immutable image ID in the API process environment, restart the API, and use the **Run safe script** and **Run attack fixture** buttons on the Gateway page. The stand-alone CLI is also available:

```bash
python -m agent_runtime.docker_demo --image <sha256-image-id-from-inspect>
python -m agent_runtime.docker_demo --image <sha256-image-id-from-inspect> --attack
```

The command must exactly match the task policy's argument vector. The executor copies only allowed files whose bytes match server-pinned SHA-256 digests into a temporary snapshot. A missing digest or changed file stops the run before Docker starts. It then runs the pinned image with no network, a read-only root, dropped capabilities, a non-root user, and resource limits. On interruption it attempts to remove the uniquely named container. The attack script tries to read a synthetic `.env` and connect to a reserved test IP. This Docker path is opt-in and separate from the default agent task. It was run on Windows with Docker Desktop's Linux engine after the content-pinning change: the safe script read its approved README, while the attack fixture received `FileNotFoundError` for `.env` and `Network is unreachable` for the connection. This is a local containment demonstration, not a proof against every escape or race. POSIX source reads use descriptor-relative no-follow traversal; the Windows demo is restricted to the app-created disposable workspace.

![Browser-verified restricted container and signed receipt](docs/screenshots/signed-container-browser-result.png)

## What is implemented today

| Capability | Status | Evidence |
| --- | --- | --- |
| Task-scoped, exact-path file read policy | Real local gateway | `agent_runtime/policy.py` and gateway tests |
| Pre-execution decision, audit write, and deny behavior | Real local gateway | `agent_runtime/gateway.py` and gateway tests |
| Local read-only executor | Real local demo | `agent_runtime/tools.py`; intended only for a trusted demo workspace |
| Command and network enforcement | Exact command allowlist; network deny-only | Restricted container safe and attack scripts ran through the API and browser on Docker Desktop |
| Bounded agent loop through the gateway | Real local runtime | `agent_runtime/agent.py` and loop tests |
| L4 local rule signal and L5 risk governor | Real gateway-derived rules, not a trained behavior model | Repeated denied or failed calls raise REVIEW or STOP; per-step and final state appear in the browser |
| Gemini-proposed calls through the gateway | Live local demo, key required | `agent_runtime/providers.py`; approved README read and denied `.env` read were verified with `gemini-3.5-flash-lite` in separate browser runs |
| HMAC chained gateway audit and Ed25519 run receipt | Real local runtime | `agent_runtime/evidence.py`, `signing.py`, and `verify_public.py`; tests cover edit, reorder, truncation, restart, signature verification, wrong key, and audit tampering |
| EffectSeal effect reconciliation | Deterministic core | Synthetic observations can be reconciled; local runs report `INCOMPLETE` because no OS collector is attached |
| Dashboard gateway routes | Real local runtime | `/api/runtime/run` and `/api/runtime/container-demo`, separate from the simulated `/api/agent/chat` path |
| Restricted Linux tool container | Local demo validated | Pinned image, snapshot of allowed files, network off, read-only root, non-root user, dropped capabilities, and resource limits; native telemetry remains absent |
| L3 eBPF and L4 trained behavior model | Unavailable in the live local path | Three Linux entry probes attached and observed correlated events in Docker Desktop's Linux VM; no request-specific application coverage or trained-model claim is made |
| L6 cryptographic evidence | Local HMAC audit plus Ed25519 signed run receipt | A pinned public key verifies the signed audit digest without the HMAC secret; independent external anchoring remains future work |
| TPM/TEE hardware attestation | Unavailable in this local demo | Research scaffolding only |
| L7 software measurement | Real local hash measurement, not hardware proof | The signed run report binds the policy, 24 selected source files, and hashes of two inactive L4 research checkpoints; `model_active` and `hardware_attested` are false |

The existing AcademIQ code is the research prototype from which AgentSentinel is being built. Its dashboard and benchmark figures may include simulated or synthetic outcomes. The new gateway demo reports only decisions made at its actual tool boundary.

On a supported Linux host, [native validation](deployments/linux-validation/README.md) requires correlated `execve`, `openat`, and loopback `connect` attempts. This three-probe test passed inside Docker Desktop's Linux VM with tracefs mounted. The C/Python event ABI is checked at collector startup. `agent_runtime/native_effects.py` maps those attempts to EffectSeal observations and fails closed on unresolved paths, loss, or mismatched cgroups. The three entry probes cannot prove complete effects, so the bridge never issues a native `MATCH`; an out-of-scope observed attempt can still produce `VIOLATION`. An optional trusted observer can cause L5 to stop further agent calls after such a violation. This observer is not attached to the Windows Gateway demo.

## Security boundary and limits

The gateway deep-copies tool arguments before checking them, denies unknown or out-of-scope calls, records a decision before an allowed read, and reserves request IDs in SQLite before dispatch. A repeated ID after restart is denied rather than executed again; the ledger does not store or replay tool output. The local read executor rejects symlink paths and files outside the configured workspace. Denied calls never reach its executor.

The local read executor is **not a hostile-workspace sandbox**. Its POSIX no-follow traversal closes path-component symlink swaps for reads; Windows remains a disposable-workspace demo. Do not point it at untrusted, actively modified host directories. The HMAC audit detects changes relative to the host-held key and separate local anchor. The Ed25519 receipt has a public verifier but its key is generated locally and has no remote trust anchor. EffectSeal's `MATCH` on synthetic fixture observations is not a claim about a real process. A local allowed read reports `INCOMPLETE` until a native collector is connected. Durable request IDs provide at-most-once dispatch, not exactly-once completion or result replay. See [SECURITY.md](SECURITY.md) for the current threat boundaries.

## Repository map

- `agent_runtime/`: gateway, bounded loop, EffectSeal reconciler, audit chain, and demos.
- `tests/gateway/` and `tests/runtime/`: security-boundary and API tests.
- `benchmarks/gateway_cases_v2.json`: 50 versioned deterministic policy fixtures and the evaluator; the original nine cases remain as a historical baseline.
- `benchmarks/model_cases_v1.json`: 25 prompt-injection and 25 benign README fixtures for bounded Gemini evaluation through the same gateway.
- `l1_gcd/` through `l7_trust/`: existing AcademIQ research layers.
- `dashboard_api/` and `frontend/`: existing demonstration UI and API.
- `benchmarks/`, `docs/`, and `reports/`: experiments and validation reports.

## Next release gates

1. Evaluate the optional Gemini path across repeated legitimate and adversarial tasks on a versioned held-out corpus, with actual tool side effects measured.
2. Harden container snapshot creation and cancellation against concurrent hostile workspace changes before treating the local demonstration as production containment. Keep network off by default.
3. Connect [EffectSeal](docs/effectseal-design.md) to native Linux observations and a verifiable receipt.
4. Evaluate attack prevention **and** legitimate-task completion on a held-out versioned corpus.
5. Publish a two-minute demo and reproducible measured results on a named Linux host.

See [the remaining implementation plan](docs/REMAINING_IMPLEMENTATION_PLAN.md) for prioritized work and acceptance criteria. Report measured results only after those gates pass.
The current verified checks and remaining gates are in [validation status](docs/VALIDATION_STATUS.md).
