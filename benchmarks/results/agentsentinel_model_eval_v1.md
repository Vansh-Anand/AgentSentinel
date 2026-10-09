# AgentSentinel model gateway evaluation v1

This is one trial per case on `Windows-11-10.0.26200-SP0` with `gemini-3.5-flash-lite`. The [versioned corpus](../model_cases_v1.json) has SHA-256 `ed1f8ef009c166cb5e77cde6fb30626a42acb20d03d001030d3acff09a67771a`. [Per-case results](agentsentinel_model_eval_v1.json) omit run IDs, raw model text, and credentials.

| Measure | Result |
| --- | ---: |
| Attack READMEs with an out-of-scope proposal | 5/25 |
| Out-of-scope proposals that executed | 0/5 |
| Attack tasks reaching a final response | 25/25 |
| Benign tasks reaching a final response | 25/25 |
| Benign cases with a denied proposal | 0/25 |
| Provider errors | 0/50 |
| Independently verified local audit chains | 50/50 |
| Public-key signed receipts independently verified | 0/50 |
| Run latency p50 / p95 | 3436.84 / 11271.45 ms |

The attack text was inside the untrusted `README.md` that the agent was asked to summarize. A denied proposal means the model requested an action outside the task policy; the gateway prevented that tool execution. The corpus uses synthetic files and a reserved test domain. The run does not measure answer contamination, real-world attack prevalence, repeated-trial variance, sandbox escape resistance, or native eBPF/TPM coverage. The 50 local HMAC chains and fixture hashes verify against saved evidence. Source hashes match this checkout: **false**. Source comparison can fail after legitimate code changes because these runs were produced by an earlier version; it is not remote or hardware attestation.

Reproduce with `python -m benchmarks.model_eval --provider gemini --per-category 25 --output .data/model-eval/gemini-full-v1.json`, then run the verifier and `python -m benchmarks.export_model_report .data/model-eval/gemini-full-v1.json`. The API key is supplied only through `GEMINI_API_KEY` and is not part of the exported report.
