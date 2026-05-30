#!/usr/bin/env python3
"""Combine GPT and OpenRouter-Claude detector-validation summaries."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GPT_LABELS = ROOT / "experiments" / "validation" / "reruns" / "detector-validation-rerun-labels.csv"
GPT_RESULTS = ROOT / "experiments" / "validation" / "reruns" / "detector-validation-rerun-results.jsonl"
CLAUDE_LABELS = (
    ROOT
    / "experiments"
    / "validation"
    / "openrouter-claude-reruns"
    / "detector-validation-openrouter-claude-labels.csv"
)
CLAUDE_LEDGER = (
    ROOT
    / "experiments"
    / "validation"
    / "openrouter-claude-reruns"
    / "detector-validation-openrouter-claude-ledger.jsonl"
)
PRO_RUNNER_PATH = ROOT / "experiments" / "scripts" / "pro-six-model-replication.py"
OUT_PATH = ROOT / "experiments" / "validation" / "detector-validation-combined-summary.md"


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


def load_jsonl_by_sample(path: Path) -> dict[str, dict]:
    rows = {}
    if not path.exists():
        return rows
    with path.open() as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                rows[row["sample_id"]] = row
    return rows


def load_csv(path: Path, source: str) -> list[dict]:
    if not path.exists():
        return []
    with path.open() as f:
        rows = [row for row in csv.DictReader(f) if row.get("manual_label")]
    for row in rows:
        row["source"] = source
    return rows


def openrouter_cost() -> float:
    total = 0.0
    if not CLAUDE_LEDGER.exists():
        return total
    with CLAUDE_LEDGER.open() as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                if row.get("status") == "ok":
                    total += float(row.get("estimated_cost_usd") or 0.0)
    return total


def main() -> None:
    pro = load_pro_runner()
    prompts = {p.id: p for p in pro.MAIN_PROMPTS}
    gpt_results = load_jsonl_by_sample(GPT_RESULTS)
    rows = load_csv(GPT_LABELS, "gpt-codex-rerun") + load_csv(CLAUDE_LABELS, "openrouter-claude-rerun")

    original = Counter()
    patched = Counter()
    by_source = defaultdict(Counter)
    by_model = defaultdict(Counter)
    by_cwe = defaultdict(Counter)
    by_prompt = defaultdict(Counter)
    patched_mismatches = []

    for row in rows:
        manual = truthy(row["manual_label"])
        original_detector = truthy(row["rerun_detector_label"])
        original[matrix_key(original_detector, manual)] += 1

        patched_detector = original_detector
        if row["source"] == "gpt-codex-rerun":
            result = gpt_results[row["sample_id"]]
            prompt = prompts[result["prompt_id"]]
            patched_detector = bool(prompt.detector(pro.extract_code(result["raw_response"])))

        key = matrix_key(patched_detector, manual)
        patched[key] += 1
        by_source[row["source"]][key] += 1
        by_model[row["model_id"]][key] += 1
        by_cwe[row["cwe"]][key] += 1
        by_prompt[row["prompt_id"]][key] += 1
        if key in {"FP", "FN"}:
            patched_mismatches.append((key, row))

    def rates(counter: Counter) -> tuple[float, float, float]:
        total = sum(counter.values())
        accuracy = (counter["TP"] + counter["TN"]) / total if total else 0.0
        precision = counter["TP"] / (counter["TP"] + counter["FP"]) if counter["TP"] + counter["FP"] else 0.0
        recall = counter["TP"] / (counter["TP"] + counter["FN"]) if counter["TP"] + counter["FN"] else 0.0
        return accuracy, precision, recall

    original_acc, original_prec, original_rec = rates(original)
    patched_acc, patched_prec, patched_rec = rates(patched)

    lines = [
        "# Combined Detector Validation Summary",
        "",
        "This combines the GPT-family full-output validation rerun and the OpenRouter Claude-family validation rerun.",
        "It validates the patched detector used for future extensions; it does not retroactively change the already-collected 2,160-row preview-only dataset.",
        "",
        "## Coverage",
        "",
        f"- Total manually labeled rows: {sum(patched.values())}",
        f"- GPT-family rows: {sum(by_source['gpt-codex-rerun'].values())}",
        f"- Claude-family rows: {sum(by_source['openrouter-claude-rerun'].values())}",
        f"- OpenRouter Claude estimated cost: ${openrouter_cost():.4f}",
        "",
        "## Recorded Detector Labels on Labeled Reruns",
        "",
        f"- TP: {original['TP']}",
        f"- TN: {original['TN']}",
        f"- FP: {original['FP']}",
        f"- FN: {original['FN']}",
        f"- Accuracy: {original_acc:.3f}",
        f"- Precision: {original_prec:.3f}",
        f"- Recall: {original_rec:.3f}",
        "",
        "## Patched Detector on Labeled Reruns",
        "",
        f"- TP: {patched['TP']}",
        f"- TN: {patched['TN']}",
        f"- FP: {patched['FP']}",
        f"- FN: {patched['FN']}",
        f"- Accuracy: {patched_acc:.3f}",
        f"- Precision: {patched_prec:.3f}",
        f"- Recall: {patched_rec:.3f}",
        "",
        "## Patched Detector by Model",
        "",
        "| Model | TP | TN | FP | FN |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for model in sorted(by_model):
        c = by_model[model]
        lines.append(f"| {model} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## Patched Detector by CWE", "", "| CWE | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"])
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        lines.append(f"| {cwe} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## Patched Detector by Prompt", "", "| Prompt | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"])
    for prompt in sorted(by_prompt):
        c = by_prompt[prompt]
        lines.append(f"| {prompt} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## Interpretation", ""])
    if patched_mismatches:
        lines.append("Patched detector mismatches remain:")
        for key, row in patched_mismatches:
            lines.append(
                f"- {key}: `{row['source']}` `{row['sample_id']}` `{row['model_id']}` "
                f"`{row['prompt_id']}` — {row['manual_notes']}"
            )
    else:
        lines.append(f"No patched-detector mismatches were observed in the combined {sum(patched.values())}-row manually labeled slice.")
    lines.extend(
        [
            "",
            "The original detector produced the known GPT-slice errors: prose-only HTTP refusals false-positive and JavaScript `Function(...)` dynamic execution false-negative. The patched detector fixes both observed failure modes in this slice.",
            "",
            "Next step before archival submission: use the patched detector from the start in the non-API or four-arm extension; expand validation to 120 rows only if reviewers require a larger audit sample.",
            "",
        ]
    )

    OUT_PATH.write_text("\n".join(lines))
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
