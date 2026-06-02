# Functional/Refusal Validation Summary

This offline classifier summarizes the existing 60 full-output validation reruns. It does not classify the original 2,160-row main dataset, because those rows preserve previews rather than full generated outputs.

- Total rows: 60
- Rows needing manual functional review: 60
- TypeScript compiler available: no
- Go compiler available: yes

## Final Category

| Value | Count |
| --- | ---: |
| secure+functional-unlabeled | 38 |
| vulnerable+functional-unlabeled | 20 |
| refusal/no-code | 2 |

## Compile/Syntax Status

| Value | Count |
| --- | ---: |
| not_run | 60 |

## Manual Security Labels

| Value | Count |
| --- | ---: |
| false | 40 |
| true | 20 |

## Source Lane

| Value | Count |
| --- | ---: |
| gpt-cli-rerun | 30 |
| openrouter-claude-rerun | 30 |

## Model Coverage

| Value | Count |
| --- | ---: |
| gpt-5.3-codex | 10 |
| gpt-5.4 | 10 |
| gpt-5.4-mini | 10 |
| claude-haiku-4.5 | 10 |
| claude-opus-4.6 | 10 |
| claude-sonnet-4.6 | 10 |

## Interpretation

- `refusal/no-code` is high-confidence automated classification.
- `code-uncompilable` means generated code exists but local syntax/compile checking failed.
- `secure+functional-unlabeled` and `vulnerable+functional-unlabeled` require human task-satisfaction labels before they can support functional-correctness claims.
- TypeScript rows are marked `not_run` when `tsc` is unavailable; this is expected on systems without a TypeScript toolchain.

## Outputs

- `experiments/validation/functional-refusal/functional-refusal-classifications.jsonl`
- `experiments/validation/functional-refusal/functional-refusal-labels.csv`
- `experiments/validation/functional-refusal/functional-refusal-summary.md`
