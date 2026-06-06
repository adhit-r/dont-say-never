#!/usr/bin/env python3
"""Run an offline structural detector audit over the full-output validation slice.

The main replication uses lightweight CWE-specific detectors. This audit gives
reviewers a reproducible check over the 60 manually labeled full-output reruns:
for each row, apply the patched extraction and language-aware detector from the
final runner, then compare it to the human security label.

This is not a full static-analysis pass. It is a practical semantic sanity
check for the observed detector failure modes: refusal/prose-only outputs and
dynamic execution via `Function(...)` rather than literal `eval(...)`.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRO_RUNNER_PATH = ROOT / "experiments" / "scripts" / "pro-six-model-replication.py"
INPUTS = [
    {
        "lane": "gpt-cli-rerun",
        "results": ROOT / "experiments" / "validation" / "reruns" / "detector-validation-rerun-results.jsonl",
        "labels": ROOT / "experiments" / "validation" / "reruns" / "detector-validation-rerun-labels.csv",
    },
    {
        "lane": "openrouter-claude-rerun",
        "results": ROOT
        / "experiments"
        / "validation"
        / "openrouter-claude-reruns"
        / "detector-validation-openrouter-claude-results.jsonl",
        "labels": ROOT
        / "experiments"
        / "validation"
        / "openrouter-claude-reruns"
        / "detector-validation-openrouter-claude-labels.csv",
    },
]
OUT_MD = ROOT / "experiments" / "validation" / "semantic-detector-audit.md"


def load_pro_runner():
    spec = importlib.util.spec_from_file_location("pro_runner", PRO_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {PRO_RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def read_labels(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    return {row["rerun_id"]: row for row in csv.DictReader(path.open()) if row.get("manual_label")}


def truthy(value: str) -> bool:
    return value.strip().lower() == "true"


def matrix_key(detector: bool, manual: bool) -> str:
    if detector and manual:
        return "TP"
    if not detector and not manual:
        return "TN"
    if detector and not manual:
        return "FP"
    return "FN"


def main() -> None:
    pro = load_pro_runner()
    prompt_by_id = {p.id: p for p in pro.MAIN_PROMPTS}

    rows = []
    for source in INPUTS:
        labels = read_labels(source["labels"])
        for row in read_jsonl(source["results"]):
            label = labels.get(row["rerun_id"])
            if not label:
                continue
            prompt = prompt_by_id[row["prompt_id"]]
            code = pro.extract_code(row.get("raw_response") or row.get("code") or "")
            structural = bool(prompt.detector(code))
            manual = truthy(label["manual_label"])
            rows.append(
                {
                    "lane": source["lane"],
                    "model_id": row["model_id"],
                    "prompt_id": row["prompt_id"],
                    "cwe": row["cwe"],
                    "condition": row["condition"],
                    "structural_detector": structural,
                    "manual_label": manual,
                    "matrix": matrix_key(structural, manual),
                    "manual_notes": label.get("manual_notes", ""),
                }
            )

    overall = Counter(r["matrix"] for r in rows)
    by_lane = defaultdict(Counter)
    by_cwe = defaultdict(Counter)
    by_prompt = defaultdict(Counter)
    by_model = defaultdict(Counter)
    mismatches = []
    for row in rows:
        by_lane[row["lane"]][row["matrix"]] += 1
        by_cwe[row["cwe"]][row["matrix"]] += 1
        by_prompt[row["prompt_id"]][row["matrix"]] += 1
        by_model[row["model_id"]][row["matrix"]] += 1
        if row["matrix"] in {"FP", "FN"}:
            mismatches.append(row)

    def rate_line(counter: Counter) -> str:
        total = sum(counter.values())
        accuracy = (counter["TP"] + counter["TN"]) / total if total else 0.0
        precision = counter["TP"] / (counter["TP"] + counter["FP"]) if counter["TP"] + counter["FP"] else 0.0
        recall = counter["TP"] / (counter["TP"] + counter["FN"]) if counter["TP"] + counter["FN"] else 0.0
        return f"accuracy={accuracy:.3f}, precision={precision:.3f}, recall={recall:.3f}"

    lines = [
        "# Semantic Detector Audit",
        "",
        "This offline audit applies the patched code-extraction and structural CWE detectors from `experiments/scripts/pro-six-model-replication.py` to the 60 manually labeled full-output validation reruns.",
        "",
        "Scope boundary: this is a practical structural sanity check, not a full AST/Semgrep proof. It specifically audits the failure modes observed in the first detector pass: prose-only/refusal false positives and CWE-94 false negatives through JavaScript `Function(...)` constructors.",
        "",
        "## Overall",
        "",
        f"- Rows audited: {sum(overall.values())}",
        f"- TP: {overall['TP']}",
        f"- TN: {overall['TN']}",
        f"- FP: {overall['FP']}",
        f"- FN: {overall['FN']}",
        f"- Rates: {rate_line(overall)}",
        "",
        "## By Validation Lane",
        "",
        "| Lane | TP | TN | FP | FN |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for lane in sorted(by_lane):
        c = by_lane[lane]
        lines.append(f"| {lane} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## By CWE", "", "| CWE | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"])
    for cwe in sorted(by_cwe):
        c = by_cwe[cwe]
        lines.append(f"| {cwe} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## By Prompt", "", "| Prompt | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"])
    for prompt_id in sorted(by_prompt):
        c = by_prompt[prompt_id]
        lines.append(f"| {prompt_id} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## By Model", "", "| Model | TP | TN | FP | FN |", "| --- | ---: | ---: | ---: | ---: |"])
    for model_id in sorted(by_model):
        c = by_model[model_id]
        lines.append(f"| {model_id} | {c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} |")

    lines.extend(["", "## Mismatches", ""])
    if mismatches:
        for row in mismatches:
            lines.append(
                f"- {row['matrix']}: `{row['lane']}` `{row['model_id']}` "
                f"`{row['prompt_id']}` `{row['condition']}` — {row['manual_notes']}"
            )
    else:
        lines.append("No structural-detector mismatches were observed in this manually labeled 60-row slice.")

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The audit supports using the patched detector for the extension suites and supports the paper's bounded claim of detector-counted insecure API use. It does not convert the preview-only main 2,160-row dataset into a full manual or full-static-analysis audit.",
            "",
        ]
    )

    OUT_MD.write_text("\n".join(lines))
    print(f"Wrote {OUT_MD}")


if __name__ == "__main__":
    main()
