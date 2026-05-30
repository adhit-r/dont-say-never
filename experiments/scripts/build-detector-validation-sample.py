#!/usr/bin/env python3
"""
Build a deterministic detector-validation sample from the final pro-replication
dataset.

Important: the existing 2,160-trial JSON files preserve only code_preview, not
full code. This script therefore creates a validation index and labeling
template, but it also marks every row as preview_only unless a future dataset
contains the full `code` field.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "experiments" / "data" / "pro-replication" / "main"
OUT_DIR = ROOT / "experiments" / "validation"
OUT_JSONL = OUT_DIR / "detector-validation-sample.jsonl"
OUT_CSV = OUT_DIR / "detector-validation-labels.csv"
OUT_SUMMARY = OUT_DIR / "detector-validation-summary.md"


FIELDNAMES = [
    "sample_id",
    "model_id",
    "model_name",
    "provider",
    "prompt_id",
    "cwe",
    "language",
    "condition",
    "trial",
    "detector_label",
    "code_length",
    "full_code_available",
    "manual_label",
    "manual_confidence",
    "manual_notes",
]


def load_rows() -> list[dict]:
    rows: list[dict] = []
    for path in sorted(DATA_DIR.glob("*.json")):
        with path.open() as f:
            payload = json.load(f)
        for row in payload.get("results", []):
            if row.get("error"):
                continue
            rows.append(row)
    return rows


def choose_sample(rows: list[dict]) -> list[dict]:
    """
    Choose up to two rows per (model, prompt, condition):
    one vulnerable detector-positive and one detector-negative where available.

    This yields a balanced label-aware sample without over-representing the
    large negative class in low-vulnerability conditions.
    """
    sample: list[dict] = []
    by_cell: dict[tuple[str, str, str], list[dict]] = {}
    for row in rows:
        key = (row["model_id"], row["prompt_id"], row["condition"])
        by_cell.setdefault(key, []).append(row)

    for key in sorted(by_cell):
        cell = sorted(by_cell[key], key=lambda r: r["trial"])
        positives = [r for r in cell if r.get("vulnerable")]
        negatives = [r for r in cell if not r.get("vulnerable")]
        if positives:
            sample.append(positives[0])
        if negatives:
            sample.append(negatives[0])
    return sample


def public_row(i: int, row: dict) -> dict:
    return {
        "sample_id": f"dv-{i:04d}",
        "model_id": row["model_id"],
        "model_name": row.get("model_name", row["model_id"]),
        "provider": row.get("provider", ""),
        "prompt_id": row["prompt_id"],
        "cwe": row["cwe"],
        "language": row["language"],
        "condition": row["condition"],
        "trial": row["trial"],
        "detector_label": bool(row.get("vulnerable")),
        "code_length": row.get("code_length", 0),
        "full_code_available": bool(row.get("code")),
        "code": row.get("code", ""),
        "code_preview": row.get("code_preview", ""),
        "manual_label": "",
        "manual_confidence": "",
        "manual_notes": "",
    }


def write_outputs(sample: list[dict], total_rows: int) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    public = [public_row(i + 1, row) for i, row in enumerate(sample)]

    with OUT_JSONL.open("w") as f:
        for row in public:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    with OUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in public:
            writer.writerow({k: row[k] for k in FIELDNAMES})

    full_code_count = sum(1 for row in public if row["full_code_available"])
    detector_pos = sum(1 for row in public if row["detector_label"])
    detector_neg = len(public) - detector_pos
    cells = {(row["model_id"], row["prompt_id"], row["condition"]) for row in public}

    OUT_SUMMARY.write_text(
        "\n".join(
            [
                "# Detector Validation Sample",
                "",
                f"Total final dataset rows scanned: {total_rows}",
                f"Validation sample rows: {len(public)}",
                f"Cells represented: {len(cells)}",
                f"Detector-positive rows: {detector_pos}",
                f"Detector-negative rows: {detector_neg}",
                f"Rows with full code available: {full_code_count}",
                "",
                "## Status",
                "",
                "The current 2,160-trial result files preserve `code_preview` only, not full generated code.",
                "This sample is therefore an index and labeling template, not a complete manual-validation artifact.",
                "",
                "Future strengthening runs must use `experiments/scripts/pro-six-model-replication.py` after the full-code preservation patch, which stores the extracted `code` field for each result.",
                "",
                "## Files",
                "",
                f"- JSONL sample: `{OUT_JSONL.relative_to(ROOT)}`",
                f"- Labeling CSV: `{OUT_CSV.relative_to(ROOT)}`",
                "",
                "## Manual Label Schema",
                "",
                "- `manual_label`: `true`, `false`, or `unclear`.",
                "- `manual_confidence`: `high`, `medium`, or `low`.",
                "- `manual_notes`: short explanation of the vulnerability decision.",
                "",
                "## Recommended Next Step",
                "",
                "Rerun this sampled validation set, or the non-API/four-arm extension, with full-code preservation enabled. Then manually annotate full outputs and report detector precision by CWE class.",
                "",
            ]
        )
    )


def main() -> None:
    rows = load_rows()
    sample = choose_sample(rows)
    write_outputs(sample, len(rows))
    print(f"Wrote {OUT_JSONL}")
    print(f"Wrote {OUT_CSV}")
    print(f"Wrote {OUT_SUMMARY}")


if __name__ == "__main__":
    main()
