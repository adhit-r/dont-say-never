#!/usr/bin/env python3
"""Summarize manual labels for detector-validation reruns."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LABELS_PATH = ROOT / "experiments" / "validation" / "reruns" / "detector-validation-rerun-labels.csv"
RESULTS_PATH = ROOT / "experiments" / "validation" / "reruns" / "detector-validation-rerun-results.jsonl"
OUT_PATH = ROOT / "experiments" / "validation" / "reruns" / "detector-validation-rerun-summary.md"
PRO_RUNNER_PATH = ROOT / "experiments" / "scripts" / "pro-six-model-replication.py"


def truthy(value: str) -> bool:
    return value.strip().lower() == "true"


def matrix_key(detector: bool, manual: bool) -> str:
    return "TP" if detector and manual else "TN" if not detector and not manual else "FP" if detector else "FN"


def load_pro_runner():
    spec = importlib.util.spec_from_file_location("pro_runner", PRO_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {PRO_RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_results_by_sample_id() -> dict[str, dict]:
    rows = {}
    if not RESULTS_PATH.exists():
        return rows
    with RESULTS_PATH.open() as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                rows[row["sample_id"]] = row
    return rows


def main() -> None:
    with LABELS_PATH.open() as f:
        rows = list(csv.DictReader(f))
    results_by_sample_id = load_results_by_sample_id()
    pro = load_pro_runner()
    prompts = {p.id: p for p in pro.MAIN_PROMPTS}

    labeled = [r for r in rows if r["manual_label"].strip()]
    matrix = Counter()
    patched_matrix = Counter()
    by_cwe = defaultdict(Counter)
    by_prompt = defaultdict(Counter)
    mismatches = []
    patched_mismatches = []

    for row in labeled:
        detector = truthy(row["rerun_detector_label"])
        manual = truthy(row["manual_label"])
        key = matrix_key(detector, manual)
        matrix[key] += 1
        by_cwe[row["cwe"]][key] += 1
        by_prompt[row["prompt_id"]][key] += 1
        if key in {"FP", "FN"}:
            mismatches.append((key, row))

        result = results_by_sample_id.get(row["sample_id"])
        if result:
            prompt = prompts[result["prompt_id"]]
            patched_code = pro.extract_code(result["raw_response"])
            patched_detector = bool(prompt.detector(patched_code))
            patched_key = matrix_key(patched_detector, manual)
            patched_matrix[patched_key] += 1
            if patched_key in {"FP", "FN"}:
                patched_mismatches.append((patched_key, row))

    total = sum(matrix.values())
    precision = matrix["TP"] / (matrix["TP"] + matrix["FP"]) if matrix["TP"] + matrix["FP"] else 0.0
    recall = matrix["TP"] / (matrix["TP"] + matrix["FN"]) if matrix["TP"] + matrix["FN"] else 0.0
    accuracy = (matrix["TP"] + matrix["TN"]) / total if total else 0.0
    patched_total = sum(patched_matrix.values())
    patched_precision = (
        patched_matrix["TP"] / (patched_matrix["TP"] + patched_matrix["FP"])
        if patched_matrix["TP"] + patched_matrix["FP"]
        else 0.0
    )
    patched_recall = (
        patched_matrix["TP"] / (patched_matrix["TP"] + patched_matrix["FN"])
        if patched_matrix["TP"] + patched_matrix["FN"]
        else 0.0
    )
    patched_accuracy = (
        (patched_matrix["TP"] + patched_matrix["TN"]) / patched_total if patched_total else 0.0
    )

    lines = [
        "# Detector Validation Rerun Summary",
        "",
        "This is a bounded manual audit of regenerated full outputs. It does not replace the full 2,160-trial dataset; it identifies detector risks that should be corrected before larger extensions.",
        "",
        "## Overall Confusion Matrix",
        "",
        f"- Labeled rows: {total}",
        f"- True positives: {matrix['TP']}",
        f"- True negatives: {matrix['TN']}",
        f"- False positives: {matrix['FP']}",
        f"- False negatives: {matrix['FN']}",
        f"- Accuracy: {accuracy:.3f}",
        f"- Precision: {precision:.3f}",
        f"- Recall: {recall:.3f}",
        "",
        "## Patched Detector Check",
        "",
        "The current runner includes two detector fixes found by this audit: refusal-only prose is treated as no generated code, and JavaScript `Function(...)` constructors count as CWE-94 dynamic execution.",
        "",
        f"- Labeled rows rechecked: {patched_total}",
        f"- True positives: {patched_matrix['TP']}",
        f"- True negatives: {patched_matrix['TN']}",
        f"- False positives: {patched_matrix['FP']}",
        f"- False negatives: {patched_matrix['FN']}",
        f"- Accuracy: {patched_accuracy:.3f}",
        f"- Precision: {patched_precision:.3f}",
        f"- Recall: {patched_recall:.3f}",
        "",
        "## By CWE",
        "",
        "| CWE | TP | TN | FP | FN |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        lines.append(f"| {cwe} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(
        [
            "",
            "## By Prompt",
            "",
            "| Prompt | TP | TN | FP | FN |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for prompt in sorted(by_prompt):
        c = by_prompt[prompt]
        lines.append(f"| {prompt} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## Mismatches", ""])
    if not mismatches:
        lines.append("No mismatches in the labeled subset.")
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
            f"The {total}-row GPT-only validation slice found two material detector risks:",
            "",
            "1. CWE-319 false positives: prose refusals that quote an unsafe `http://` URL were counted as vulnerable even though no code was generated.",
            "2. CWE-94 false negatives: dynamic execution through `Function(...)` or `new Function(...)` was missed by the original `eval(...)` detector.",
            "",
            "The runner has been patched for future runs to treat refusal-only prose as no generated code and to detect JavaScript `Function` constructors as CWE-94 dynamic execution.",
            f"In this labeled slice, those patches change the detector from {matrix['FP'] + matrix['FN']} mismatches to {patched_matrix['FP'] + patched_matrix['FN']} mismatches.",
            "",
            "Claude-family validation is tracked separately under `experiments/validation/openrouter-claude-reruns/`.",
            "",
        ]
    )

    OUT_PATH.write_text("\n".join(lines))
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
