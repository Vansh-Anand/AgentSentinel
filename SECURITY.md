# Security scope

AgentSentinel is a research and portfolio application. Its default task runs against a synthetic repository with a synthetic `.env`; it does not accept an arbitrary host workspace. The API and UI should be bound to loopback as shown in the quickstart and `compose.yaml`. Do not publish the unauthenticated demo API to the internet.

## Boundaries that are implemented

- The server owns the task policy and checks each typed proposal before calling an executor.
- Allowed and denied requests are recorded in a local HMAC audit; completed runs have a locally signed Ed25519 receipt. Copy and pin the public key separately before treating a verification result as independent of the API host.
- The optional command fixture runs in a pinned local Docker image with no network, a read-only root, a non-root user, dropped capabilities, and a snapshot containing only allowlisted files. The default Compose profile does not mount the Docker socket and therefore does not enable this optional fixture.

## Known limits

- On Windows, local host file reads are intended only for the app-created disposable workspace. POSIX hosts use descriptor-relative no-follow traversal; a hostile concurrently mutable Windows workspace is not a supported source.
- Container snapshot and cancellation hardening has focused tests, but no comprehensive escape or race evaluation. Do not use the fixture as a production sandbox.
- L3 `execve`, `openat`, and `connect` attempt probes attached and produced correlated events inside Docker Desktop's Linux VM. This does not prove native host-wide coverage or request-specific process-tree correlation. No request-level EffectSeal correlation is live in the application; allowed local actions report `INCOMPLETE`.
- L4 in the live Gateway is a deterministic rule signal. No trained anomaly model is claimed.
- L7 local software hashes do not establish loaded-code integrity or TPM/TEE attestation. A simulated quote cannot pass hardware verification.
- A locally held signing key and anchor can both be changed by an attacker who controls the API host. External anchoring and independent key custody are not implemented.
- The 50-case model result is one trial per case from an earlier source revision. It does not establish general prompt-injection immunity.

To report a security issue, open a private GitHub security advisory for this repository if available, or contact the maintainer privately. Avoid putting real secrets in public issues or demo inputs.
