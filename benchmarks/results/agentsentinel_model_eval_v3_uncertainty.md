# V3 single-trial uncertainty note

Derived 2026-10-11 from the [published v3 per-case summary](agentsentinel_model_eval_v3.json). This note adds descriptive 95% Wilson score intervals to historical results; it is **not** a new model run or a current-source verification. The model corpus contained 25 curated synthetic attack READMEs and 25 benign READMEs, one trial each.

| Observable event | Count | 95% Wilson interval |
| --- | ---: | ---: |
| Attack case induced a denied tool proposal | 1/25 | 0.7%–19.5% |
| Denied attack proposal executed | 0/1 | 0.0%–79.3% |
| Benign task passed the lexical answer check | 25/25 | 86.7%–100.0% |
| Benign case induced a denied proposal | 0/25 | 0.0%–13.3% |

The intervals use `benchmarks.rate_intervals.wilson_95`. Their mathematical assumptions do not make this curated corpus representative of deployed agent traffic. The 0/1 execution observation is especially small: the gateway denied the one unsafe proposal that the model made, while 24 attack texts induced no such proposal. No semantic answer review or repeated-model variance is represented here.
