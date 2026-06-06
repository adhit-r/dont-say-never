#!/usr/bin/env python3
"""Summarize the 360-row full-output validation plan and rerun outputs.

This script is offline. It does not call models. It reads the deterministic
plan generated from `experiments/data/pro-replication/main/` and, when present,
the rerun `results.jsonl` and manual `labels.csv` artifacts for the same
validation ids.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = ROOT / "experiments" / "validation" / "full-output-360"
DEFAULT_PLAN_PATH = DEFAULT_OUT_DIR / "plan.jsonl"
DEFAULT_RESULTS_PATH = DEFAULT_OUT_DIR / "results.jsonl"
DEFAULT_LABELS_PATH = DEFAULT_OUT_DIR / "labels.csv"
DEFAULT_SUMMARY_PATH = DEFAULT_OUT_DIR / "summary.md"

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


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_labels(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    with path.open() as f:
        return {
            row["validation_id"]: row
            for row in csv.DictReader(f)
            if row.get("validation_id")
        }


def normalize_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def normalize_bool_label(value: object) -> str:
    text = normalize_text(value).lower()
    if text in {"true", "false", "unclear"}:
        return text
    return "unlabeled"


def sort_known_first(values: set[str], preferred: list[str]) -> list[str]:
    preferred_index = {value: idx for idx, value in enumerate(preferred)}
    return sorted(values, key=lambda value: (preferred_index.get(value, len(preferred)), value))


def matrix_key(predicted: bool, manual: bool) -> str:
    if predicted and manual:
        return "TP"
    if not predicted and not manual:
        return "TN"
    if predicted and not manual:
        return "FP"
    return "FN"


def bool_from_label(value: object) -> bool | None:
    text = normalize_text(value).lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def rate_line(counter: Counter) -> str:
    total = sum(counter.values())
    accuracy = (counter["TP"] + counter["TN"]) / total if total else 0.0
    precision = counter["TP"] / (counter["TP"] + counter["FP"]) if counter["TP"] + counter["FP"] else 0.0
    recall = counter["TP"] / (counter["TP"] + counter["FN"]) if counter["TP"] + counter["FN"] else 0.0
    return f"accuracy={accuracy:.3f}, precision={precision:.3f}, recall={recall:.3f}"


def table(counter: Counter, order: list[str]) -> list[str]:
    lines = ["| Value | Count |", "| --- | ---: |"]
    for key in order:
        lines.append(f"| {key} | {counter.get(key, 0)} |")
    for key in sorted(set(counter) - set(order)):
        lines.append(f"| {key} | {counter[key]} |")
    return lines


def build_summary(plan: list[dict], results: list[dict], labels: dict[str, dict]) -> str:
    plan_by_id = {row["validation_id"]: row for row in plan if row.get("validation_id")}
    results_by_id = {row["validation_id"]: row for row in results if row.get("validation_id")}
    planned_ids = set(plan_by_id)
    result_ids = set(results_by_id)
    label_template_rows = len(labels)
    manual_security_filled = sum(
        1 for row in labels.values() if normalize_bool_label(row.get("manual_security_label")) != "unlabeled"
    )
    manual_functional_filled = sum(
        1 for row in labels.values() if normalize_bool_label(row.get("manual_functional_label")) != "unlabeled"
    )
    any_manual_filled = sum(
        1
        for row in labels.values()
        if normalize_bool_label(row.get("manual_security_label")) != "unlabeled"
        or normalize_bool_label(row.get("manual_functional_label")) != "unlabeled"
    )

    by_model = Counter(row["source_model_id"] for row in plan)
    by_prompt = Counter(row["source_prompt_id"] for row in plan)
    by_condition = Counter(row["source_condition"] for row in plan)
    by_model_prompt = Counter((row["source_model_id"], row["source_prompt_id"]) for row in plan)
    original_detector = Counter("true" if row["original_detector_label"] else "false" for row in plan)

    lines = [
        "# Full-Output 360 Validation Summary",
        "",
        "This summary covers the deterministic 360-row rerun plan derived from `experiments/data/pro-replication/main/`.",
        "It stays bounded to the fresh full-output rerun artifacts; it does not recover the original preview-only outputs.",
        "",
        "## Coverage",
        "",
        f"- Planned rows: {len(plan)}",
        f"- Planned rows with results: {len(result_ids)}",
        f"- Label template rows: {label_template_rows}",
        f"- Rows with any filled manual label: {any_manual_filled}",
        f"- Rows with filled manual security labels: {manual_security_filled}",
        f"- Rows with filled manual functional labels: {manual_functional_filled}",
        f"- Missing planned rows in results: {len(planned_ids - result_ids)}",
        f"- Extra result rows not in plan: {len(result_ids - planned_ids)}",
        f"- Rows per model/prompt pair: {next(iter(by_model_prompt.values()), 0)}",
        "",
        "## Planned Balance",
        "",
        f"- Models: {len(by_model)}",
        f"- Prompts: {len(by_prompt)}",
        f"- Conditions: {len(by_condition)}",
        "",
        "| Dimension | Value | Rows |",
        "| --- | --- | ---: |",
    ]
    for model_id in sort_known_first(set(by_model), MODELS):
        lines.append(f"| Model | {model_id} | {by_model[model_id]} |")
    for prompt_id in sort_known_first(set(by_prompt), PROMPTS):
        lines.append(f"| Prompt | {prompt_id} | {by_prompt[prompt_id]} |")
    for condition in sort_known_first(set(by_condition), CONDITIONS):
        lines.append(f"| Condition | {condition} | {by_condition[condition]} |")

    lines += [
        "",
        "## Original Detector Mix",
        "",
        "| Original detector label | Rows |",
        "| --- | ---: |",
        f"| true | {original_detector['true']} |",
        f"| false | {original_detector['false']} |",
    ]

    if result_ids:
        rerun_detector = Counter()
        rerun_vs_manual = Counter()
        rerun_vs_original = Counter()
        matched_rows = 0
        manual_ready_rows = 0

        for validation_id, result in results_by_id.items():
            rerun_value = result.get("rerun_detector_label", result.get("detector_label", result.get("original_detector_label")))
            rerun_bool = bool_from_label(rerun_value)
            if rerun_bool is None:
                continue
            rerun_detector["true" if rerun_bool else "false"] += 1
            matched_rows += 1

            plan_row = plan_by_id.get(validation_id, {})
            original_bool = bool(plan_row.get("original_detector_label"))
            rerun_vs_original[matrix_key(rerun_bool, original_bool)] += 1

            manual_row = labels.get(validation_id, {})
            manual_bool = bool_from_label(
                manual_row.get("manual_security_label", result.get("manual_security_label"))
            )
            if manual_bool is not None:
                rerun_vs_manual[matrix_key(rerun_bool, manual_bool)] += 1
                manual_ready_rows += 1

        lines += [
            "",
            "## Rerun Detector Coverage",
            "",
            f"- Rows with an explicit rerun detector label: {matched_rows}",
            f"- Rows with manual security labels available for comparison: {manual_ready_rows}",
            "",
            "| Rerun detector label | Rows |",
            "| --- | ---: |",
            f"| true | {rerun_detector['true']} |",
            f"| false | {rerun_detector['false']} |",
            "",
            "### Rerun vs Original",
            "",
            "| Matrix | Rows |",
            "| --- | ---: |",
        ]
        for key in ["TP", "TN", "FP", "FN"]:
            lines.append(f"| {key} | {rerun_vs_original[key]} |")

        if manual_ready_rows:
            lines += [
                "",
                "### Rerun vs Manual Security Labels",
                "",
                "| Matrix | Rows |",
                "| --- | ---: |",
            ]
            for key in ["TP", "TN", "FP", "FN"]:
                lines.append(f"| {key} | {rerun_vs_manual[key]} |")
            lines += [
                "",
                f"- Rates: {rate_line(rerun_vs_manual)}",
            ]

    if labels:
        manual_security = Counter(normalize_bool_label(row.get("manual_security_label")) for row in labels.values())
        manual_functional = Counter(
            normalize_bool_label(row.get("manual_functional_label")) for row in labels.values()
        )
        compile_status = Counter(normalize_text(row.get("compile_status")).lower() or "unlabeled" for row in labels.values())
        final_category = Counter(normalize_text(row.get("final_category")).lower() or "unlabeled" for row in labels.values())

        manual_review_rows = sum(
            1 for row in labels.values() if normalize_bool_label(row.get("manual_functional_label")) == "unlabeled"
        )

        lines += [
            "",
            "## Manual Labels",
            "",
            f"- Rows needing manual functional review: {manual_review_rows}",
            "",
            "### Manual Security Label",
            "",
        ]
        lines.extend(table(manual_security, ["true", "false", "unclear", "unlabeled"]))
        lines += [
            "",
            "### Manual Functional Label",
            "",
        ]
        lines.extend(table(manual_functional, ["true", "false", "unclear", "unlabeled"]))
        lines += [
            "",
            "### Compile / Syntax Status",
            "",
        ]
        lines.extend(table(compile_status, ["pass", "fail", "not_run", "unlabeled"]))
        lines += [
            "",
            "### Final Category",
            "",
        ]
        lines.extend(table(final_category, []))

    lines += [
        "",
        "## Files",
        "",
        f"- Plan: `{DEFAULT_PLAN_PATH.relative_to(ROOT)}`",
        f"- Results: `{DEFAULT_RESULTS_PATH.relative_to(ROOT)}`",
        f"- Manual labels: `{DEFAULT_LABELS_PATH.relative_to(ROOT)}`",
        "",
        "## Claim Boundary",
        "",
        "Rows generated from this plan should be described as a fresh full-output validation rerun. They validate detector behavior and sampled rerun behavior; they do not retroactively recover the exact original full outputs.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN_PATH)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS_PATH)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS_PATH)
    parser.add_argument("--out", type=Path, default=DEFAULT_SUMMARY_PATH)
    args = parser.parse_args()

    plan = load_jsonl(args.plan)
    results = load_jsonl(args.results)
    labels = load_labels(args.labels)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_summary(plan, results, labels))
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
