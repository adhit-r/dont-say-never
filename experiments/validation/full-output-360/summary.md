# Full-Output 360 Validation Summary

This summary covers the deterministic 360-row rerun plan derived from `experiments/data/pro-replication/main/`.
It stays bounded to the fresh full-output rerun artifacts; it does not recover the original preview-only outputs.

## Coverage

- Planned rows: 360
- Planned rows with results: 0
- Label template rows: 360
- Rows with any filled manual label: 0
- Rows with filled manual security labels: 0
- Rows with filled manual functional labels: 0
- Missing planned rows in results: 360
- Extra result rows not in plan: 0
- Rows per model/prompt pair: 10

## Planned Balance

- Models: 6
- Prompts: 6
- Conditions: 3

| Dimension | Value | Rows |
| --- | --- | ---: |
| Model | gpt-5.4 | 60 |
| Model | gpt-5.4-mini | 60 |
| Model | gpt-5.3-codex | 60 |
| Model | claude-opus-4.6 | 60 |
| Model | claude-sonnet-4.6 | 60 |
| Model | claude-haiku-4.5 | 60 |
| Prompt | eval-usage | 60 |
| Prompt | md5-hash | 60 |
| Prompt | http-url | 60 |
| Prompt | insecure-random | 60 |
| Prompt | eval-dynamic | 60 |
| Prompt | weak-hash | 60 |
| Condition | control | 120 |
| Condition | negative-framing | 120 |
| Condition | positive-framing | 120 |

## Original Detector Mix

| Original detector label | Rows |
| --- | ---: |
| true | 130 |
| false | 230 |

## Manual Labels

- Rows needing manual functional review: 360

### Manual Security Label

| Value | Count |
| --- | ---: |
| true | 0 |
| false | 0 |
| unclear | 0 |
| unlabeled | 360 |

### Manual Functional Label

| Value | Count |
| --- | ---: |
| true | 0 |
| false | 0 |
| unclear | 0 |
| unlabeled | 360 |

### Compile / Syntax Status

| Value | Count |
| --- | ---: |
| pass | 0 |
| fail | 0 |
| not_run | 0 |
| unlabeled | 360 |

### Final Category

| Value | Count |
| --- | ---: |
| unlabeled | 360 |

## Files

- Plan: `experiments/validation/full-output-360/plan.jsonl`
- Results: `experiments/validation/full-output-360/results.jsonl`
- Manual labels: `experiments/validation/full-output-360/labels.csv`

## Claim Boundary

Rows generated from this plan should be described as a fresh full-output validation rerun. They validate detector behavior and sampled rerun behavior; they do not retroactively recover the exact original full outputs.
