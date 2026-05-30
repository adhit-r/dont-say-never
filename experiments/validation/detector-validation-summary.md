# Detector Validation Sample

Total final dataset rows scanned: 2160
Validation sample rows: 160
Cells represented: 108
Detector-positive rows: 63
Detector-negative rows: 97
Rows with full code available: 0

## Status

The current 2,160-trial result files preserve `code_preview` only, not full generated code.
This sample is therefore an index and labeling template, not a complete manual-validation artifact.

Future strengthening runs must use `experiments/scripts/pro-six-model-replication.py` after the full-code preservation patch, which stores the extracted `code` field for each result.

## Files

- JSONL sample: `experiments/validation/detector-validation-sample.jsonl`
- Labeling CSV: `experiments/validation/detector-validation-labels.csv`

## Manual Label Schema

- `manual_label`: `true`, `false`, or `unclear`.
- `manual_confidence`: `high`, `medium`, or `low`.
- `manual_notes`: short explanation of the vulnerability decision.

## Recommended Next Step

Rerun this sampled validation set, or the non-API/four-arm extension, with full-code preservation enabled. Then manually annotate full outputs and report detector precision by CWE class.
