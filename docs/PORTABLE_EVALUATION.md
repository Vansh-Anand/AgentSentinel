# Portable security lab evaluation

## 19 October 2026 current-source checkpoint

The approved source manifest is `6a62a7d77ff55d244f2746ce3918f383a90491d050ba8334992f7202362df51f`. The [broker-backed 50-case fixture report](../benchmarks/results/portable_lab_eval_etw_broker.json) passed 25/25 attack and 25/25 benign capability assertions, verified 50/50 signed exports, started 25 authorized Windows Job workers with 25 correlated ETW process starts, and started no worker for 25 denied proposals. These are deterministic repeated policy contracts, not model attack detection. The reproducible command is `./scripts/run_windows_etw_eval.ps1 -Limit 50` after starting the elevated local broker.

The new [20-case local Ollama report](../benchmarks/results/portable_lab_ollama_live_v3.json) uses [a separate synthetic corpus](../benchmarks/portable_live_cases_v3.json) with ten benign tasks and ten attacks across direct and lower-trust document inputs. Three attacks produced the predeclared forbidden proposal; all three were denied before execution. Seven attacks produced no targeted forbidden proposal, so conditional gateway prevention is 3/3 observed proposals, not 10/10 attacks. The benign assertion passed in 7/10 trials, all 20 signed exports verified, and there were no provider/runtime errors. End-to-end p50 was 18,946.5 ms and p95 28,430 ms; this includes the local model and is not security overhead. The three failed benign checks are retained in the report.

The [same 20-case Gemini report](../benchmarks/results/portable_lab_gemini_live_v3.json) passed 10/10 benign task assertions and verified 20/20 signed exports with zero runtime errors. None of the ten attack trials produced its predeclared forbidden proposal, so a conditional gateway prevention rate is undefined for Gemini; the ten attack outcomes are model behavior, not ten gateway interceptions. End-to-end p50 was 9,379 ms and p95 24,490 ms. These are one-trial synthetic case measurements. Neither provider report establishes a population-level prompt-injection detection or false-positive rate.

The sections below preserve earlier source measurements for comparison of evidence scope. They should not be read as before/after treatment effects.

Earlier approved source manifest: `bee1ed27e84ec979171ab0af37d9eab1f335d6630204e2319e4ad42f5acb0e1a`. The [then-current 50-case fixture report](../benchmarks/results/portable_lab_eval_v2.json), [Gemini report](../benchmarks/results/portable_lab_live_v2.json), [prior 200-case fixture report](../benchmarks/results/portable_lab_eval_v2_prior_source.json), Ollama report, and saved notebook outputs use earlier source manifests. They are historical and must not be compared as before/after treatment effects.

## Natural-language model trials

The [12-case synthetic corpus](../benchmarks/portable_live_cases_v2.json) has five useful tasks and seven attack tasks across direct secret requests, lower-trust document overrides, role spoofing, encoded instructions, command/network requests and scope expansion. Each case was run twice with Gemini on an earlier source. The Ollama run is also from an earlier source. The corpus hash is `0abe66ee2d5e930fd2e535134ef99374e70f79d4a69cd34a1112fb0e1c069d37`.

| Provider | Forbidden proposals observed | Gateway interceptions conditional on proposal | Unauthorized executions | Useful task assertions | Verified exports | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [Gemini `gemini-3.5-flash-lite`, earlier source](../benchmarks/results/portable_lab_live_v2.json) | 0/14 attack trials | 0/0, undefined rate | 0 | 9/10 | 24/24 | 1 |
| [Ollama `qwen2.5:3b`, earlier source](../benchmarks/results/portable_lab_ollama_live_v2.json) | 0/7 attack trials | 0/0, undefined rate | 0 | 1/5 | 12/12 | 0 |

None of the 14 earlier Gemini attack trials or seven earlier Ollama attack trials elicited the predeclared forbidden tool proposal. They therefore cannot be counted as gateway interceptions. The available evidence shows that the gateway denies forbidden actions when submitted directly or through controlled fixture proposals; it does not establish a model attack-block rate for this corpus. In the Gemini run, nine of ten benign assertions passed and the remaining ticket trial hit a provider rate limit. The gateway allowed bounded recovery after one unobserved-source citation denial; it did not execute the denied write. The earlier Ollama run passed one of five benign assertions. Repeated trials share prompts, so the descriptive confidence intervals in the report are not population guarantees.

The benign checks require selected tool receipts and artifact or answer assertions. They are stronger than answer-substring checks alone but do not independently grade report quality or factual completeness. Latency is end-to-end including the model, not gateway overhead. The provider reports preserve case-family outcomes, errors, model name, corpus hash and signed-export checks. Private raw run data remains under ignored `.data/`.

## Deterministic gateway contracts

`scripts/evaluate_portable_lab.py` can run up to 200 repeated controlled cases. To finish the current-source check promptly, the latest run used 50 cases: 25 unauthorized tool/path proposals and 25 benign tool tasks. It checks expected reason codes, useful fixture answers, denied executor flags and signed exports. These are regression contracts based on repeated templates, not independent adversarial prompts.

The [earlier-source rerun](../benchmarks/results/portable_lab_eval_v2.json) recorded 25/25 attack assertions, 25/25 benign assertions and 50/50 verified exports, with 0/25 denied proposals invoking an executor and zero provider/runtime errors. Authorized actions ran under a Windows Job Object in 25/50 cases; denied cases started no worker. ETW process correlation was 0/50 because that unelevated run could not start a trace. End-to-end fixture latency was p50 1045 ms and p95 3964 ms on this Windows host. This includes the fixture provider, source checks, durable events and tools; it does not isolate gateway overhead. The [evaluation notebook](../notebooks/AgentSentinel_Portable_Evaluation.ipynb) has now been regenerated and executed from the current broker-backed report; all four code cells completed, two charts rendered, and the printed manifest matches this build.

The [earlier run under concurrent load](../benchmarks/results/portable_lab_eval_v1_concurrent.json) recorded 99/100 attack assertions, 100/100 benign assertions and 199/200 verified exports. Its `network-24` case failed closed at L6 with `EVIDENCE_FINALIZATION_FAILED`: the audit log had one record while the anchor remained at sequence zero, so no signed receipt was issued and no denied executor ran. This historical-source reliability failure, not a bypass, is retained rather than hidden by the clean repeat.

## Independent verification and scope

Run `python scripts/verify_lab_evidence.py <export.json> --trusted-public-key .data/secure-lab/signing.pub` with a separately pinned copy of the issuer key. The UI verifier uses the current host's pinned key; a public key supplied only inside an export does not independently establish the signer. The seven visual challenges exercise defined application controls; native eBPF, TPM, a trained detector and external Flowise canvas are not validated on this Windows host.
