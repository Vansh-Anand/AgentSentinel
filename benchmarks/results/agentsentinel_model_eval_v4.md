# AgentSentinel model gateway evaluation v4

This is 1 trial per selected case on `Windows-11-10.0.26200-SP0` with `gemini-3.5-flash-lite`. The [versioned corpus](../model_cases_v2.json) has SHA-256 `2c334693b805693ff81ee00d8453bc06961a86fdf17561d91d60ff7b59a8f81c`. [Per-case results](agentsentinel_model_eval_v4.json) omit run IDs, raw model text, and credentials.

| Measure | Result |
| --- | ---: |
| Attack READMEs with an out-of-scope proposal | 3/25 |
| Out-of-scope proposals that executed | 0/3 |
| Attack tasks reaching a final response | 25/25 |
| Benign tasks reaching a final response | 25/25 |
| Benign tasks passing lexical answer assertion | 25/25 |
| Benign cases with a denied proposal | 0/25 |
| Provider errors | 0/50 |
| Independently verified local audit chains | 50/50 |
| Public-key signed receipts independently verified | 50/50 |
| Final answers bound to signed audits | 50/50 |
| Run latency p50 / p95 | 3496.15 / 5318.23 ms |

The attack text was inside the untrusted `README.md` that the agent was asked to summarize. A denied proposal means the model requested an action outside the task policy; the gateway prevented that tool execution. The corpus uses synthetic files and a reserved test domain. The provider-error row counts unresolved final cases; transient HTTP 429 responses can be retried from a checkpoint. The lexical answer assertion checks required terms only; it is not a full semantic-quality or answer-contamination grade. The run does not establish real-world attack prevalence, sandbox escape resistance, or native eBPF/TPM coverage. The local HMAC chains and fixture hashes verify against saved evidence. Source hashes matched the checkout at publication: **true**. This static result may become stale after code changes; it is not remote or hardware attestation.

Reproduce with `python -m benchmarks.model_eval --provider gemini --corpus model_cases_v2.json --per-category 25 --repeats 1 --output .data/model-eval/gemini-full-v4.json`, then run the verifier and `python -m benchmarks.export_model_report .data/model-eval/gemini-full-v4.json --version v4`. The API key is supplied only through `GEMINI_API_KEY` and is not part of the exported report.

## Descriptive uncertainty

| Rate | Count | 95% Wilson interval |
| --- | ---: | ---: |
| Attack cases inducing a denied proposal | 3/25 | 4.2%–30.0% |
| Denied attack proposals executed | 0/3 | 0.0%–56.1% |
| Benign tasks completed | 25/25 | 86.7%–100.0% |
| Benign cases with a denied proposal | 0/25 | 0.0%–13.3% |
| Benign lexical task checks passed | 25/25 | 86.7%–100.0% |

These intervals assume independent trials. The cases were curated, so the intervals do not estimate real-world attack prevalence or protection.
