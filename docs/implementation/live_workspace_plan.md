# Live document workspace implementation

## Findings and scope

The existing FastAPI/React application already enforces tool policies, exact-action
approval, durable events and signed exports. Main runs currently materialize a fixed
synthetic catalog. Windows workers reconstruct that same catalog. Sessions are
anonymous bearer capabilities on a loopback API, not authenticated user accounts.
Existing uncommitted changes are preserved. Knowledge-graph tools are unavailable;
source inspection is the fallback.

## Delivery checklist

- [x] Live provider is the primary chat path; no fixture fallback.
- [x] UTF-8 text/Markdown/CSV uploads, opaque IDs, quotas and session scope.
- [x] Server-created per-run snapshots and catalog hashes; no arbitrary paths.
- [x] Dynamic policy and trusted worker catalog; actual reports/downloads.
- [x] Distinct layer descriptions, inputs, decisions and unavailable states.
- [x] Behavioral limits and action-bound governance remain independently enforced.
- [x] Windows limits/ETW claims remain bounded by actual receipts.
- [x] Security/API/frontend regressions and build pass.
- [x] Live browser scenarios verified, with screenshots and explicit gaps.
- [x] Threat model, reproducible demo and final verification report.

## Phases

1. Add transactional document storage/API and snapshot tests.
2. Bind uploaded snapshots to runtime policy, provider context and Windows workers.
3. Add upload selection and live chat defaults, then per-layer explanations.
4. Verify error/authorization/approval/evidence boundaries and browser flows.
5. Review changes, approve measured baseline, document results and limitations.

## Acceptance and limits

Custom documents must produce genuine read/report effects; foreign resource IDs,
invalid uploads and undeclared capabilities must fail. A denied action launches no
worker. A model refusal is not a gateway denial. Fixtures remain available only as
explicit verification. Upload data may be sent to the selected model, so the UI
must disclose the destination. Host/API is trusted. Anonymous session loss means
loss of access; this is not production multi-user authentication. Job Objects are
resource containment, ETW is process observation, L7 is software measurement.
An external ticket adapter may be delivered without a live submission if no test
destination/credentials are configured; this must remain labelled unverified.

## Outcome

Core live-workspace phases are implemented and verified; see [verification](../audit/live_workspace_verification.md) and [demo](../frontend/live-workspace-demo.md). Optional external ticket submission and PDF parsing remain explicitly excluded/unavailable, not simulated. ETW remains an optional existing process-observation path; current browser startup uses Windows Job workers.
