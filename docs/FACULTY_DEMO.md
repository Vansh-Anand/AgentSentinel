# AgentSentinel faculty demonstration

**Current walkthrough (17 October 2026):** [Product release and three-minute demonstration](PRODUCT_RELEASE_2026-10-17.md). Start at `/overview`, run a useful task or a document attack in the chat-style `/lab`, then open the separate Layer trace and Detailed results. The instructions below describe an older interface and are retained only for historical comparison.

## Historical walkthrough

**Current workbench:** use the [portable release walkthrough](PORTABLE_RELEASE.md). It covers the seven controlled guards, useful tools, custom live-model prompts, approvals, policy comparison and independent evidence verification. The earlier read-only demonstration below is retained at `/lab/classic`; its controls are not the current `/lab` interface.

## Start and open

From the repository root, run `./scripts/start_faculty_demo.ps1` and open `http://127.0.0.1:5178/lab`. The launcher serves the API on 8008 and the UI on 5178, checks readiness, and records process IDs and logs in ignored `.data/faculty-demo`. Stop its recorded processes with `./scripts/stop_faculty_demo.ps1`. The fixture replay works without Gemini or Ollama. If Ollama is installed and running with `qwen2.5:3b`, the provider selector enables **Ollama · local live model**. Gemini becomes available when the locally stored credential and SDK work; provider failures remain visible instead of being replaced with fixture results.

For the Windows ETW demonstration, use `./scripts/start_etw_demo.ps1 -ApiPort 8010 -UiPort 5180 -EtwPort 8011` and open `http://127.0.0.1:5180/lab`. Approve elevation for the narrow ETW broker only; the API and UI remain ordinary user processes. Run **Calculate** to show a Job-assigned worker plus an independently observed process-start/stop pair with zero reported event loss in Detailed Results. Then run **Forbidden secret** to show L2 denial before worker launch. Stop all three processes with `./scripts/stop_faculty_demo.ps1`. ETW is process-lifecycle observation, not a file/network sandbox or a prompt-injection detector.

## Two-minute live walkthrough

1. Open **Live Lab**. Keep **Prompt injection** and **Fixture replay**. The main box is now **Attack prompt in document**; its text is inserted into a disposable `README.md` when the run starts. Press **Run agent**. The **What happened to your attack** card shows the source, `read_file → .env`, `PATH_OUT_OF_SCOPE`, and the fact that the executor was not invoked. The **Seven-layer flow** animates through actual received checkpoints; use **Replay flow** if the faculty member wants to watch it again. The detailed trace supplies real backend timestamps. The fixture is deterministic and is clearly labeled as replay, not a model.
2. Switch to **Benign task** and rerun. The README read is allowed and the executor is invoked. No denied action occurs; the result says **No unauthorized action observed**. An allowed read has `INCOMPLETE` EffectSeal telemetry on this Windows host because no native collector is attached.
3. For a custom case, edit the main attack prompt. Expand **Demo context and document** only if you want to change the legitimate task or background facts. Choose **Ollama** for an installed local model or **Gemini** when its service is healthy. The fixture recognizes only its preset phrases. A live model may avoid any forbidden proposal yet still repeat the untrusted instruction in its answer. In that case, the result says **No forbidden tool proposal observed**; it does not prove a gateway interception. Ollama's first README read is an orchestrator step labeled separately from its later model response.
4. Expand **Test a proposed action directly**. Enter a custom file path such as `.env`, a command such as `python -c print(42)`, or a URL. The real gateway returns the policy reason and `Executor invoked: no`. This proves the policy boundary independently of model behavior and is labeled as a manual proposal.
5. Open **Evidence**, select the run ID, and show the verified HMAC audit and Ed25519 receipt. Download the signed evidence ZIP if needed. Returning to a past run reads saved evidence; it does not rerun the model.

## What to say about the seven layers

The live claim is a task-scoped pre-execution tool gateway, a bounded agent loop, visible policy decisions, and locally verifiable evidence. The UI's technical drawer reports each layer's actual mode. Linux eBPF observation and TPM-backed attestation were not validated on this Windows host. Some research challenge checks are replay rules or simulations; open them from **Research** if asked, and keep that distinction explicit.

## Troubleshooting

- If the ports are occupied, stop the recorded demo process with `./scripts/stop_faculty_demo.ps1` or pass free `-ApiPort` and `-UiPort` values to the launcher. It will not silently attach to an older app.
- If the local model is disabled, start Ollama and confirm `ollama list` includes `qwen2.5:3b`, then refresh Live Lab. Fixture replay and direct policy probes remain available while a model is offline.
- If Gemini reports a quota, timeout, or provider error, keep the error visible and use Ollama or fixture replay. Neither alternative is represented as a successful Gemini run.
- Only enter synthetic text. The demo workspace contains a made-up README and `.env`; it does not mount or expose the host project to the agent.
