#!/usr/bin/env python3
"""Build a deterministic full-output validation rerun plan.

The main 2,160-row dataset stores code previews only. This script creates a
fresh rerun plan that preserves the original model/prompt/condition/trial
metadata while making clear that generated outputs must be collected again.

Default target: 360 rows = 10 rows per model x prompt pair, balanced to
120 rows per condition using a rotating 4/3/3 allocation.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "experiments" / "data" / "pro-replication" / "main"
DEFAULT_OUT_DIR = ROOT / "experiments" / "validation" / "full-output-360"

MODELS = [
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.3-codex",
    "claude-opus-4.6",
    "claude-sonnet-4.6",
    "claude-haiku-4.5",
]

PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]
CONDITIONS = ["control", "negative-framing", "positive-framing"]

LABEL_FIELDS = [
    "validation_id",
    "source_model_id",
    "source_prompt_id",
    "source_condition",
    "source_trial",
    "provider",
    "cwe",
    "language",
    "original_detector_label",
    "rerun_detector_label",
    "has_code",
    "code_length",
    "manual_security_label",
    "manual_security_confidence",
    "manual_security_notes",
    "manual_functional_label",
    "manual_functional_confidence",
    "manual_functional_notes",
    "compile_status",
    "compile_detail",
    "reviewer_id",
    "second_reviewer_label",
    "adjudicated_label",
    "final_category",
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


def condition_allocation(pair_index: int, rows_per_pair: int) -> dict[str, int]:
    if rows_per_pair % 3 != 1:
        raise ValueError("rows_per_pair must equal 3k+1 for balanced rotating allocation")
    base = rows_per_pair // 3
    allocation = {condition: base for condition in CONDITIONS}
    allocation[CONDITIONS[pair_index % len(CONDITIONS)]] += 1
    return allocation


def choose_trials(cell_rows: list[dict], n: int) -> list[dict]:
    """Choose rows with deterministic detector-label diversity.

    Prefer an alternating positive/negative detector-label mix when both classes
    exist, then fill by trial order. The rerun is stochastic and fresh; original
    trial ids are retained only as deterministic sampling anchors.
    """
    positives = sorted([r for r in cell_rows if r.get("vulnerable")], key=lambda r: r["trial"])
    negatives = sorted([r for r in cell_rows if not r.get("vulnerable")], key=lambda r: r["trial"])
    selected: list[dict] = []
    while len(selected) < n and (positives or negatives):
        if positives:
            selected.append(positives.pop(0))
            if len(selected) >= n:
                break
        if negatives:
            selected.append(negatives.pop(0))
    if len(selected) < n:
        selected_ids = {id(r) for r in selected}
        for row in sorted(cell_rows, key=lambda r: r["trial"]):
            if id(row) not in selected_ids:
                selected.append(row)
            if len(selected) >= n:
                break
    return selected[:n]


def build_plan(rows: list[dict], rows_per_model_prompt: int) -> list[dict]:
    by_cell: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for row in rows:
        by_cell[(row["model_id"], row["prompt_id"], row["condition"])].append(row)

    plan: list[dict] = []
    pair_index = 0
    for model_id in MODELS:
        for prompt_id in PROMPTS:
            allocation = condition_allocation(pair_index, rows_per_model_prompt)
            pair_index += 1
            for condition in CONDITIONS:
                cell = by_cell[(model_id, prompt_id, condition)]
                chosen = choose_trials(cell, allocation[condition])
                if len(chosen) != allocation[condition]:
                    raise RuntimeError(
                        f"Insufficient rows for {model_id}/{prompt_id}/{condition}: "
                        f"needed {allocation[condition]}, got {len(chosen)}"
                    )
                for row in chosen:
                    plan.append({
                        "validation_id": f"fo360-{len(plan) + 1:04d}",
                        "suite": "main",
                        "source_model_id": row["model_id"],
                        "source_model_name": row.get("model_name", row["model_id"]),
                        "provider": row.get("provider", ""),
                        "source_prompt_id": row["prompt_id"],
                        "source_condition": row["condition"],
                        "source_trial": row["trial"],
                        "repo": row.get("repo", ""),
                        "cwe": row["cwe"],
                        "language": row["language"],
                        "label": row.get("label", ""),
                        "original_detector_label": bool(row.get("vulnerable")),
                        "original_code_length": row.get("code_length", 0),
                        "original_code_preview": row.get("code_preview", ""),
                        "rerun_note": "Fresh full-output rerun; source_trial is a deterministic sampling anchor, not output recovery.",
                    })
    return plan


def write_outputs(plan: list[dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    plan_path = out_dir / "plan.jsonl"
    labels_path = out_dir / "labels.csv"
    summary_path = out_dir / "summary.md"
    plan_summary_path = out_dir / "plan-summary.md"

    with plan_path.open("w") as f:
        for row in plan:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    with labels_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=LABEL_FIELDS)
        writer.writeheader()
        for row in plan:
            writer.writerow({
                "validation_id": row["validation_id"],
                "source_model_id": row["source_model_id"],
                "source_prompt_id": row["source_prompt_id"],
                "source_condition": row["source_condition"],
                "source_trial": row["source_trial"],
                "provider": row["provider"],
                "cwe": row["cwe"],
                "language": row["language"],
                "original_detector_label": row["original_detector_label"],
            })

    by_condition = Counter(row["source_condition"] for row in plan)
    by_model = Counter(row["source_model_id"] for row in plan)
    by_prompt = Counter(row["source_prompt_id"] for row in plan)
    by_detector = Counter(str(row["original_detector_label"]) for row in plan)
    lines = [
        "# Full-Output 360 Validation Plan",
        "",
        "This is a deterministic rerun plan, not recovered original full output.",
        "The main 2,160-row dataset preserved code previews only; this plan samples source cells and trials as anchors for fresh reruns that must preserve raw responses and extracted code.",
        "",
        f"- Planned rows: {len(plan)}",
        f"- Models: {len(by_model)}",
        f"- Prompts: {len(by_prompt)}",
        f"- Conditions: {len(by_condition)}",
        "",
        "## Condition Balance",
        "",
        "| Condition | Rows |",
        "| --- | ---: |",
    ]
    for condition in CONDITIONS:
        lines.append(f"| {condition} | {by_condition[condition]} |")
    lines += [
        "",
        "## Original Detector-Label Mix",
        "",
        "| Original detector label | Rows |",
        "| --- | ---: |",
        f"| true | {by_detector['True']} |",
        f"| false | {by_detector['False']} |",
        "",
        "## Model Balance",
        "",
        "| Model | Rows |",
        "| --- | ---: |",
    ]
    for model_id in MODELS:
        lines.append(f"| {model_id} | {by_model[model_id]} |")
    lines += [
        "",
        "## Files",
        "",
        f"- Plan: `{plan_path.relative_to(ROOT)}`",
        f"- Label template: `{labels_path.relative_to(ROOT)}`",
        "",
        "## Claim Boundary",
        "",
        "Rows generated from this plan should be described as a fresh full-output validation rerun. They validate detector behavior and sampled rerun behavior; they do not retroactively recover the exact original full outputs.",
        "",
    ]
    summary_text = "\n".join(lines)
    summary_path.write_text(summary_text)
    plan_summary_path.write_text(summary_text)
    print(f"Wrote {plan_path}")
    print(f"Wrote {labels_path}")
    print(f"Wrote {summary_path}")
    print(f"Wrote {plan_summary_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows-per-model-prompt", type=int, default=10)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()
    rows = load_rows()
    plan = build_plan(rows, args.rows_per_model_prompt)
    write_outputs(plan, args.out_dir)


if __name__ == "__main__":
    main()
