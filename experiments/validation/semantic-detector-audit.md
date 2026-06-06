# Semantic Detector Audit

This offline audit applies the patched code-extraction and structural CWE detectors from `experiments/scripts/pro-six-model-replication.py` to the 60 manually labeled full-output validation reruns.

Scope boundary: this is a practical structural sanity check, not a full AST/Semgrep proof. It specifically audits the failure modes observed in the first detector pass: prose-only/refusal false positives and CWE-94 false negatives through JavaScript `Function(...)` constructors.

## Overall

- Rows audited: 60
- TP: 20
- TN: 40
- FP: 0
- FN: 0
- Rates: accuracy=1.000, precision=1.000, recall=1.000

## By Validation Lane

| Lane | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| gpt-cli-rerun | 8 | 22 | 0 | 0 |
| openrouter-claude-rerun | 12 | 18 | 0 | 0 |

## By CWE

| CWE | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| CWE-319 | 2 | 9 | 0 | 0 |
| CWE-328 | 5 | 13 | 0 | 0 |
| CWE-338 | 3 | 6 | 0 | 0 |
| CWE-94 | 10 | 12 | 0 | 0 |

## By Prompt

| Prompt | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| eval-dynamic | 9 | 2 | 0 | 0 |
| eval-usage | 1 | 10 | 0 | 0 |
| http-url | 2 | 9 | 0 | 0 |
| insecure-random | 3 | 6 | 0 | 0 |
| md5-hash | 3 | 6 | 0 | 0 |
| weak-hash | 2 | 7 | 0 | 0 |

## By Model

| Model | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| claude-haiku-4.5 | 7 | 3 | 0 | 0 |
| claude-opus-4.6 | 3 | 7 | 0 | 0 |
| claude-sonnet-4.6 | 2 | 8 | 0 | 0 |
| gpt-5.3-codex | 4 | 6 | 0 | 0 |
| gpt-5.4 | 2 | 8 | 0 | 0 |
| gpt-5.4-mini | 2 | 8 | 0 | 0 |

## Mismatches

No structural-detector mismatches were observed in this manually labeled 60-row slice.

## Interpretation

The audit supports using the patched detector for the extension suites and supports the paper's bounded claim of detector-counted insecure API use. It does not convert the preview-only main 2,160-row dataset into a full manual or full-static-analysis audit.
