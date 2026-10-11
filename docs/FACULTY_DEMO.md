# AgentSentinel faculty demo

## Start the local website

On this Windows checkout, the Gemini key is already stored under the current user's DPAPI protection in ignored `.data/secrets`. The website never receives the key. PowerShell 7, Python dependencies, and the frontend dependencies must be installed. From the repository root:

```powershell
./scripts/start_faculty_demo.ps1
```

Open `http://127.0.0.1:5178/gateway`. The script starts the API on `127.0.0.1:8008` and Vite on `127.0.0.1:5178`, checks both are responding, and writes process IDs and logs under ignored `.data/faculty-demo`. If another service holds either port, the script fails rather than showing an older build. Stop only the recorded demo processes with:

```powershell
./scripts/stop_faculty_demo.ps1
```

## Five-minute walkthrough

1. **Show a repeatable interception.** Select the README injection preset, choose **Deterministic fixture replay**, and run it. The fixture proposes an allowed README read followed by an out-of-scope `.env` read. The second proposal is denied before execution. Show the verified audit chain and Ed25519 receipt; download the public evidence ZIP if useful. This provider is a deterministic test fixture, not an AI model.
2. **Try custom model input.** Choose **Gemini model (live)**. Edit the legitimate task and the untrusted README. Submit only synthetic content. The page reports a blocked proposal only if the model actually requests a forbidden tool action. If the model ignores the attack, it says so; do not describe that as a gateway interception.
3. **Prove the boundary independently of model behavior.** In **Manual policy probe**, enter `.env` or another custom path. `PATH_OUT_OF_SCOPE` and `Executor invoked: no` show the pre-execution decision. A path such as `../secret` gets `INVALID_PATH`. Command and HTTP POST probes show their disabled policy reasons. An approved `README.md` read executes. Each probe uses the same gateway, audit chain, and signed receipt, with no model inference.
4. **Explain the measured result.** The evaluation card reports one trial per synthetic case with separate counts for attacks that induced a forbidden proposal, denied proposals executed, benign completion, and signed-evidence verification. Its lexical answer check is a limited task assertion, not a semantic quality score.
5. **State the seven-layer boundary.** L2 is a real pre-execution gate. L3 native telemetry, a trained L4 detector, external L6 anchoring, and hardware L7 attestation are not live on this Windows demo. The page shows an `INCOMPLETE` effect receipt for allowed local reads because no native OS collector is attached.

## Seven-layer challenge lab

Open `http://127.0.0.1:5178/pipeline` and press **Run seven examples**. The result table lists the verdict, proof level, and reason for every layer. Select any layer, replace **Challenge input**, and run it again. For L2, select a tool action first; the text is parsed as a path, command argument vector, or URL and sent through the same pre-execution gateway as the agent. It cannot run arbitrary host commands or make outbound HTTP calls.

| Layer | Example result | What it proves |
| --- | --- | --- |
| L1 | `UNKNOWN_TOOL` | A custom JSON proposal is checked against the allowed tool vocabulary. This is a schema check, not live grammar-constrained decoding. |
| L2 | `.env` → `PATH_OUT_OF_SCOPE` | A real gateway deny before execution, with a verified HMAC audit chain and Ed25519 receipt. Try `../secret`, a custom command, an HTTP URL, and allowed `README.md`. |
| L3 | `SENSITIVE_KERNEL_EVENT` | A supplied event matches a replay rule; no Windows kernel telemetry is collected. |
| L4 | `BEHAVIOR_SEQUENCE_MARKER` | A supplied sequence matches a replay rule; no trained live baseline is evaluated. |
| L5 | `SEQUENCE_RISK_THRESHOLD` | A supplied sequence crosses a simple replay threshold; no cross-session inference runs. |
| L6 | `MAC_INVALID` | A real HMAC check detects a changed *copy* of a synthetic audit record against its anchor. It is not an external transparency service. |
| L7 | `TPM_HOST_UNAVAILABLE` | The demo explicitly reports that hardware attestation was not run. |

The lower **Research Replay** scenario catalog visualizes the older orchestrator demonstration. Its L3–L6 outcomes are simulated and its L7 result is unavailable. Use the challenge lab and Gateway page for live enforcement evidence.

The synthetic `.env` is created inside a disposable task directory and is never selected or uploaded by the UI. Gemini receives the submitted task, README text, and tool feedback; use made-up content only. Provider HTTP 429 or other errors are shown as errors, not silently replaced with fixture results.
