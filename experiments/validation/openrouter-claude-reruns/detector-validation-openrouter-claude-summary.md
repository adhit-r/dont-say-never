# OpenRouter Claude Validation Reruns

This artifact is a bounded paid validation lane used only when Claude CLI is unavailable.
It does not mutate the main 2,160-trial dataset.

## Cost and Coverage

- Completed rows: 30
- Estimated token cost: $0.1896

## Manual-Label Confusion Matrix

- True positives: 12
- True negatives: 18
- False positives: 0
- False negatives: 0
- Accuracy: 1.000
- Precision: 1.000
- Recall: 1.000

## By Model

| Model | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| claude-haiku-4.5 | 7 | 3 | 0 | 0 |
| claude-opus-4.6 | 3 | 7 | 0 | 0 |
| claude-sonnet-4.6 | 2 | 8 | 0 | 0 |

## By CWE

| CWE | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| CWE-319 | 2 | 3 | 0 | 0 |
| CWE-328 | 4 | 6 | 0 | 0 |
| CWE-338 | 2 | 3 | 0 | 0 |
| CWE-94 | 4 | 6 | 0 | 0 |

## By Prompt

| Prompt | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| eval-dynamic | 3 | 2 | 0 | 0 |
| eval-usage | 1 | 4 | 0 | 0 |
| http-url | 2 | 3 | 0 | 0 |
| insecure-random | 2 | 3 | 0 | 0 |
| md5-hash | 2 | 3 | 0 | 0 |
| weak-hash | 2 | 3 | 0 | 0 |

## Mismatches

No mismatches in this manually labeled OpenRouter Claude slice.

## Interpretation

This 30-row Claude-family validation slice is small but useful: it covers all three Claude models and all six prompts, and the patched detector agrees with manual labels on every inspected output.
It should be combined with the earlier GPT-family validation slice before writing the final detector-validation section.

## Files

- Results: `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-results.jsonl`
- Ledger: `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-ledger.jsonl`
- Manual labels: `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-labels.csv`
