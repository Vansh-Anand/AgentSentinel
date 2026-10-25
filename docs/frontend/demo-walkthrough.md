> Current main application: see [Live workspace demo](live-workspace-demo.md). The fixture walkthrough below is retained for explicitly labelled Advanced verification.

# AgentSentinel: focused faculty and interview demonstration

## Start

From the repository root in PowerShell:

```powershell
./scripts/start_faculty_demo.ps1
```

Open http://127.0.0.1:5180/lab. API: http://127.0.0.1:8010.
The launcher checks HTTP readiness, the reviewed source baseline, and Windows Job support.
If a demo is already running, use `./scripts/stop_faculty_demo.ps1` before starting it.
For optional process observation, use `./scripts/start_etw_demo.ps1` instead; Windows may request elevation for the narrow ETW broker. Core demonstrations do not require ETW.
Never approve an unknown source baseline merely to bypass an integrity error. Review the backend changes before using `python scripts/approve_lab_manifest.py --approve-current-source`.

## Explain the project in 30 seconds

AgentSentinel is an incident assistant with a server-owned tool gateway. The agent can read permitted synthetic incident documents, calculate findings, create a cited report, and create a local ticket. Every proposed action is checked before dispatch. Recorded events and signed receipts show the decision, the executor state, and observed effects.

## Three main views

- **Chat:** one prompt box, optional untrusted document attachment, three examples, compact recorded action journey. Settings contain the model provider and policy. New conversation resets the visible chat; delete removes that conversation's local records. Conversation deletion is not a secure disk-erasure feature.
- **Run details:** saved requests open into results. Inspect requested arguments, permission explanation, enforcing check, executor state, effects, and evidence verification. Download the signed evidence, report, or local ticket when available. The full seven-layer trace, Windows details, provenance and policy comparison remain available for technical discussion.
- **Evaluation:** source-matched deterministic contract checks and separately labelled live-model results. Older evaluations are not relabelled as current.

Provider status, Windows capabilities, controlled layer challenges and historical research are under **Advanced**. Legacy URLs remain accessible for compatibility and are outside the primary presentation.

## Eight-minute demonstration

1. In **Chat**, expand **Agent settings** and select **Scripted fixture** for a deterministic introduction. Explain that it is a limited parser, not model inference.
2. Choose **Investigate incidents** and Send. Show the read, calculator, report and local ticket receipts. Open **Inspect run** and download the report and ticket. Their data is synthetic; they are real local artifacts.
3. Start a new conversation. Choose **Forbidden secret** and Send. Show the actual denying checkpoint, rule code, executor not invoked, and zero effects for that denied action. Do not assume the run status alone proves prevention.
4. Start a new conversation. Choose **Document injection**. Explain that the user wants a summary, while an attached document contains a conflicting instruction. Send and inspect the README read followed by the forbidden proposal in the scripted run.
5. Open the **Technical trace**. Select an action and replay its recorded events. The visual pace is for presentation; displayed millisecond values come from the backend. Unreached layers are not passes.
6. Open **Evaluation**. State the exact case count and outcomes displayed. Repeated fixture families are regression checks, not independent real-world attacks or model detection accuracy.
7. For a custom natural-language request, select Gemini or Ollama only when configured. Type your own task or attack. Inspect the recorded proposal: a model refusal without a forbidden proposal is not a gateway interception.

## Seven security responsibilities

L7 checks an approved software manifest. L1 validates input and structured tool proposals. L4 applies a repeated-action rule. L5 applies budgets, cancellation and exact-action approvals. L2 applies tool/file permissions and source-release checks. L6 provides durable audit and signed evidence. L3 executes permitted bounded tools, with a limited Windows Job worker on the Windows demo.

These are lifecycle responsibilities, not a promise that every request passes seven sequential filters. ETW observes process events when the broker is available; it does not enforce file/network permissions. Job Objects limit resources and lifetime, not arbitrary-code confidentiality. Software hashes and host-held signing keys are not TPM attestation.

## Reproduce checks

```powershell
./scripts/verify_demo.ps1
python scripts/evaluate_portable_lab.py --provider fixture --limit 50 --output portable_lab_eval_v2.json
```

To measure the optional Windows/ETW path with an already running broker:

```powershell
./scripts/run_windows_etw_eval.ps1 -Limit 50
```

Inspect report source hashes, failure counts, denominators and limits before citing metrics. End-to-end duration includes the tool workload. No security-only overhead claim is made. Live-model evaluation requires configured credentials and an explicit choice to send synthetic inputs to that provider; it is not run by the verification script.

## Claims to defend

- Scoped tool/file authorization before dispatch.
- Action-bound approval and replay protection under the tested threat model.
- Streamed recorded events and inspectable execution receipts.
- Verifiable local audit evidence and reproducible deterministic regression.

Do not claim universal prompt-injection prevention, a trained anomaly detector, complete native visibility, hardware attestation, or production multi-user isolation. The API host and its approved baseline are trusted. Flowise is a secondary integration with its own verification status.
