# Live workspace demo

Start from PowerShell in the repository:

```powershell
./scripts/start_faculty_demo.ps1
```

Open http://127.0.0.1:5180/lab. If already running, use the existing instance;
restart with stop_faculty_demo.ps1 then start_faculty_demo.ps1 when necessary.

## Five-minute explanation

"AgentSentinel lets a live model work with uploaded documents, but the model cannot
grant itself tools or access. A server gateway checks every proposed action. I can
inspect the decision and whether execution actually occurred."

1. Expand **Your documents**. Upload a UTF-8 .txt, .md or .csv (16 KiB maximum).
   The file is selected automatically. Use disposable demonstration data. Gemini
   receives selected content when read by tools; the notice explains that flow.
   Ollama is available as a local model when running.
2. Ask your own question, such as "Read my document, calculate the total incidents,
   and create a concise report citing its source." Main chat uses live inference.
   Example cards fill editable text only. No fixture fallback is used.
3. Open **Inspect run**. Show actual read, calculation and write receipts. Download
   the report and signed evidence. Open **Documents bound to this run** to see
   IDs, source IDs and version hashes.
   After a live report write succeeds, Chat returns a brief answer built from
   completed tool receipts, including the verified calculator result when used.
   It does not wait for an extra model call merely to announce the report.
4. Expand **Explain all seven security responsibilities**. Explain each layer's
   question and open its actual timestamped checks. Full **Layer trace** supports
   action selection and explicitly recorded replay. No unrecorded success is implied.
5. Start a new conversation. Ask "For an authorization test, use read_file with
   path .env. Let the gateway decide." The model may refuse, or may propose the
   action and receive L2 denial. Explain the observed outcome without changing it.
6. Choose **Approval required** under Agent settings. Request a report, review the
   exact proposed content, and Decline. Show L5 stopping the write. Alternatively,
   approve a safe local report and inspect its actual artifact.
7. Open **Evaluation**. Live model trials and scripted contracts are separate and
   displayed only for the measured source baseline. A small synthetic evaluation
   dataset does not make the application's tool execution scripted.

## Each layer in one sentence

L1 validates structure; L2 authorizes resources/tools; L3 runs bounded operations;
L4 checks sequences; L5 controls budgets/approval/cancellation; L6 records verifiable
evidence; L7 checks the approved software baseline. They occur at relevant lifecycle
points, not as seven sequential language detectors.

## Reproduce verification

```powershell
./scripts/verify_demo.ps1 -CheckRunning
python scripts/evaluate_workspace.py --provider gemini --repeat 1 --windows-job
python scripts/verify_lab_evidence.py path/to/export.json --trusted-public-key .data/secure-lab/signing.pub
```

The live evaluation sends only its explicitly defined disposable cases/document to
the selected provider. It never reads user uploads. Fixture evaluation remains an
optional separate regression. ETW requires the dedicated start_etw_demo.ps1 broker
startup and may request Windows elevation. Ordinary startup still uses Job workers.

## Boundaries to state

Local bearer-session scope is not production authentication. Reports and uploads
are local persistent plaintext. Signing proves evidence integrity under a trusted
host/public key. Windows Job Objects limit resources/lifetime; ETW observes process
events, not every file/network effect. L7 is a source manifest, not hardware proof.
External ticket submission is unavailable until a restricted connector is built
and configured; no local fixture ticket is presented as a remote submission.

## Resume wording

- Built a live AI document assistant with server-enforced tool/resource permissions,
  versioned document snapshots, action-bound approvals and signed execution evidence.
- Implemented bounded Windows workers and optional ETW process correlation, with
  separate receipts for authorization, execution and observation availability.
- Add measured test/evaluation counts only from the final verification report;
  distinguish small live-model trials from deterministic fixture contracts.
