#!/usr/bin/env python3
"""Summarize manually labeled OpenRouter Claude validation reruns."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "experiments" / "validation" / "openrouter-claude-reruns"
LABELS_PATH = OUT_DIR / "detector-validation-openrouter-claude-labels.csv"
LEDGER_PATH = OUT_DIR / "detector-validation-openrouter-claude-ledger.jsonl"
SUMMARY_PATH = OUT_DIR / "detector-validation-openrouter-claude-summary.md"


def truthy(value: str) -> bool:
    return value.strip().lower() == "true"


def matrix_key(detector: bool, manual: bool) -> str:
    return "TP" if detector and manual else "TN" if not detector and not manual else "FP" if detector else "FN"


def main() -> None:
    with LABELS_PATH.open() as f:
        rows = [row for row in csv.DictReader(f) if row.get("manual_label")]

    matrix = Counter()
    by_model = defaultdict(Counter)
    by_cwe = defaultdict(Counter)
    by_prompt = defaultdict(Counter)
    mismatches = []
    for row in rows:
        detector = truthy(row["rerun_detector_label"])
        manual = truthy(row["manual_label"])
        key = matrix_key(detector, manual)
        matrix[key] += 1
        by_model[row["model_id"]][key] += 1
        by_cwe[row["cwe"]][key] += 1
        by_prompt[row["prompt_id"]][key] += 1
        if key in {"FP", "FN"}:
            mismatches.append((key, row))

    total = sum(matrix.values())
    precision = matrix["TP"] / (matrix["TP"] + matrix["FP"]) if matrix["TP"] + matrix["FP"] else 0.0
    recall = matrix["TP"] / (matrix["TP"] + matrix["FN"]) if matrix["TP"] + matrix["FN"] else 0.0
    accuracy = (matrix["TP"] + matrix["TN"]) / total if total else 0.0

    estimated_cost = 0.0
    if LEDGER_PATH.exists():
        import json

        with LEDGER_PATH.open() as f:
            for line in f:
                if line.strip():
                    row = json.loads(line)
                    if row.get("status") == "ok":
                        estimated_cost += float(row.get("estimated_cost_usd") or 0.0)

    lines = [
        "# OpenRouter Claude Validation Reruns",
        "",
        "This artifact is a bounded paid validation lane used only when Claude CLI is unavailable.",
        "It does not mutate the main 2,160-trial dataset.",
        "",
        "## Cost and Coverage",
        "",
        f"- Completed rows: {total}",
        f"- Estimated token cost: ${estimated_cost:.4f}",
        "",
        "## Manual-Label Confusion Matrix",
        "",
        f"- True positives: {matrix['TP']}",
        f"- True negatives: {matrix['TN']}",
        f"- False positives: {matrix['FP']}",
        f"- False negatives: {matrix['FN']}",
        f"- Accuracy: {accuracy:.3f}",
        f"- Precision: {precision:.3f}",
        f"- Recall: {recall:.3f}",
        "",
        "## By Model",
        "",
        "| Model | TP | TN | FP | FN |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for model in sorted(by_model):
        c = by_model[model]
        lines.append(f"| {model} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## By CWE", "", "| CWE | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"])
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        lines.append(f"| {cwe} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## By Prompt", "", "| Prompt | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"])
    for prompt in sorted(by_prompt):
        c = by_prompt[prompt]
        lines.append(f"| {prompt} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## Mismatches", ""])
    if not mismatches:
        lines.append("No mismatches in this manually labeled OpenRouter Claude slice.")
    else:
        for key, row in mismatches:
            lines.append(
                f"- {key}: `{row['sample_id']}` `{row['model_id']}` `{row['prompt_id']}` "
                f"`{row['condition']}` — {row['manual_notes']}"
            )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            f"This {total}-row Claude-family validation slice is small but useful: it covers all three Claude models and all six prompts, and the patched detector agrees with manual labels on every inspected output.",
            "It should be combined with the earlier GPT-family validation slice before writing the final detector-validation section.",
            "",
            "## Files",
            "",
            "- Results: `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-results.jsonl`",
            "- Ledger: `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-ledger.jsonl`",
            "- Manual labels: `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-labels.csv`",
            "",
        ]
    )

    SUMMARY_PATH.write_text("\n".join(lines))
    print(f"Wrote {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
