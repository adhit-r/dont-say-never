# Full-Output 360 Validation Plan

This is a deterministic rerun plan, not recovered original full output.
The main 2,160-row dataset preserved code previews only; this plan samples source cells and trials as anchors for fresh reruns that must preserve raw responses and extracted code.

- Planned rows: 360
- Models: 6
- Prompts: 6
- Conditions: 3

## Condition Balance

| Condition | Rows |
| --- | ---: |
| control | 120 |
| negative-framing | 120 |
| positive-framing | 120 |

## Original Detector-Label Mix

| Original detector label | Rows |
| --- | ---: |
| true | 130 |
| false | 230 |

## Model Balance

| Model | Rows |
| --- | ---: |
| gpt-5.4 | 60 |
| gpt-5.4-mini | 60 |
| gpt-5.3-codex | 60 |
| claude-opus-4.6 | 60 |
| claude-sonnet-4.6 | 60 |
| claude-haiku-4.5 | 60 |

## Files

- Plan: `experiments/validation/full-output-360/plan.jsonl`
- Label template: `experiments/validation/full-output-360/labels.csv`

## Claim Boundary

Rows generated from this plan should be described as a fresh full-output validation rerun. They validate detector behavior and sampled rerun behavior; they do not retroactively recover the exact original full outputs.
