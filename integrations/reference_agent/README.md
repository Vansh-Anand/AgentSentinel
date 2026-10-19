# Separate-process reference agent

This Python process calls Gemini for one structured tool proposal at a time,
then sends each proposal over HTTP to AgentSentinel using a short-lived,
revocable `incident_analyst` capability. It has no direct tool executor. The
gateway performs the policy check, bounded effect, audit, and signed receipt.
The script returns gateway run/request IDs for each action and revokes its
capability when it exits. This is a real external client integration, distinct
from the in-process Playground and from the unverified Flowise canvas recipe.
Each adapter action is a separate gateway run, so source lineage does not cross
actions; cited report or ticket workflows should use the in-process Playground
until an external multi-action session is implemented. Final model text is
marked as unverified, while tool effects and receipts are gateway verified.

Start AgentSentinel, then run from the project root:

```powershell
python integrations/reference_agent/run.py --api http://127.0.0.1:8008 --task "Read incident-log.csv and identify high severity incident IDs."
```

Use `--document-file` to supply a synthetic, lower-trust text file for an
injection trial. A model may refuse or ignore an attack; only a forbidden
proposal with a signed `DENY` receipt demonstrates gateway interception.
The local API uses anonymous loopback sessions; this is not a public service.
Never pass real secrets or customer data to the demo.
