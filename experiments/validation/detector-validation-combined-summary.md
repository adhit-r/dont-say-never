# Combined Detector Validation Summary

This combines the GPT-family full-output validation rerun and the OpenRouter Claude-family validation rerun.
It validates the patched detector used for future extensions; it does not retroactively change the already-collected 2,160-row preview-only dataset.

## Coverage

- Total manually labeled rows: 60
- GPT-family rows: 30
- Claude-family rows: 30
- OpenRouter Claude estimated cost: $0.1896

## Recorded Detector Labels on Labeled Reruns

- TP: 17
- TN: 35
- FP: 5
- FN: 3
- Accuracy: 0.867
- Precision: 0.773
- Recall: 0.850

## Patched Detector on Labeled Reruns

- TP: 20
- TN: 40
- FP: 0
- FN: 0
- Accuracy: 1.000
- Precision: 1.000
- Recall: 1.000

## Patched Detector by Model

| Model | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| claude-haiku-4.5 | 7 | 3 | 0 | 0 |
| claude-opus-4.6 | 3 | 7 | 0 | 0 |
| claude-sonnet-4.6 | 2 | 8 | 0 | 0 |
| gpt-5.3-codex | 4 | 6 | 0 | 0 |
| gpt-5.4 | 2 | 8 | 0 | 0 |
| gpt-5.4-mini | 2 | 8 | 0 | 0 |

## Patched Detector by CWE

| CWE | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| CWE-319 | 2 | 9 | 0 | 0 |
| CWE-328 | 5 | 13 | 0 | 0 |
| CWE-338 | 3 | 6 | 0 | 0 |
| CWE-94 | 10 | 12 | 0 | 0 |

## Patched Detector by Prompt

| Prompt | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| eval-dynamic | 9 | 2 | 0 | 0 |
| eval-usage | 1 | 10 | 0 | 0 |
| http-url | 2 | 9 | 0 | 0 |
| insecure-random | 3 | 6 | 0 | 0 |
| md5-hash | 3 | 6 | 0 | 0 |
| weak-hash | 2 | 7 | 0 | 0 |

## Interpretation

No patched-detector mismatches were observed in the combined 60-row manually labeled slice.

The original detector produced the known GPT-slice errors: prose-only HTTP refusals false-positive and JavaScript `Function(...)` dynamic execution false-negative. The patched detector fixes both observed failure modes in this slice.

Next step before archival submission: use the patched detector from the start in the non-API or four-arm extension; expand validation to 120 rows only if reviewers require a larger audit sample.
