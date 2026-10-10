# Optional independent receipt witness

AgentSentinel can export a signed audit bundle. The optional witness CLI checks
that bundle against an **independently pinned API public key**, signs its receipt
and audit digests with a separate Ed25519 key, and appends the statement to a
sequence-linked SQLite ledger. It is a protocol implementation; the current
Compose deployment has **no independent witness service** and reports only
local L6 evidence.

## Trust setup

1. Copy the API public key through an independent channel and pin it on the
   witness host. The copy inside the evidence bundle is insufficient to
   establish the API's identity.
2. Run the witness on a separately administered host/account. Keep its
   `witness-key.ed25519` and `anchors.sqlite` outside the API host and data
   volume. Back them up and restrict access. The witness key must not be sent
   back with the evidence bundle.
3. Pin `witness-key.pub` independently on the verifier. Keep a separate copy
   of the latest ledger head or ledger snapshot if append-history continuity
   must be checked across witness-host failures.

## Issue and verify one anchor

First export an existing run on the API host:

```bash
python -m agent_runtime.export_evidence RUN_ID portable-run
```

Transfer `portable-run` and the already pinned API public key to the witness
host. The witness command creates its private key on first use:

```bash
python -m agent_runtime.witness_anchor issue RUN_ID \
  --evidence-dir portable-run \
  --api-key-file pinned-api-key.pub \
  --witness-dir /independent/witness-state \
  --output RUN_ID.witness.json
```

Transfer the proof to a verifier that separately pinned both public keys:

```bash
python -m agent_runtime.witness_anchor verify RUN_ID \
  --evidence-dir portable-run \
  --proof RUN_ID.witness.json \
  --api-key-file pinned-api-key.pub \
  --witness-key-file pinned-witness-key.pub
```

If the verifier has a trusted copy of the witness ledger, add
`--witness-ledger anchors.sqlite` to check the full sequence and locate the
proof within it. The witness is idempotent for the same run and receipt; a
different receipt for an anchored run is rejected. A missing, tampered or
wrong-key proof fails verification.

## Current assurance limit

The witness signs its own clock value and a hash-chain position. This is not
an RFC 3161 trusted timestamp, a hardware quote, or proof that the witness
machine was independent. SQLite enforces append operations in the CLI; an
attacker controlling the witness host and signing key can rewrite history.
Offline proof verification alone confirms the witness signed the particular
bundle. Checking continuity requires a separately retained ledger checkpoint.
The protocol has local positive and negative tests, but independent deployment,
key rotation/revocation and compromise testing remain release gates.
