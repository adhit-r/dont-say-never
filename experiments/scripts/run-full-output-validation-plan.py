#!/usr/bin/env python3
"""Run a full-output validation plan and preserve raw outputs.

This script is intentionally separate from the main replication runner. It
creates a fresh validation artifact and does not mutate the 2,160-row dataset.
Use `--estimate-only` before any real model calls.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN = ROOT / "experiments" / "validation" / "full-output-360" / "plan.jsonl"
DEFAULT_OUT_DIR = ROOT / "experiments" / "validation" / "full-output-360"
PRO_RUNNER_PATH = ROOT / "experiments" / "scripts" / "pro-six-model-replication.py"

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


def load_pro_runner():
    spec = importlib.util.spec_from_file_location("pro_runner", PRO_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {PRO_RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_plan(path: Path) -> list[dict]:
    rows = []
    with path.open() as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def load_results(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def write_label_template(results: list[dict], out_dir: Path) -> None:
    path = out_dir / "labels.csv"
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=LABEL_FIELDS)
        writer.writeheader()
        for row in results:
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
                "rerun_detector_label": row.get("rerun_detector_label", ""),
                "has_code": row.get("has_code", ""),
                "code_length": row.get("code_length", ""),
                "compile_status": row.get("compile_status", "not_run"),
            })


def choose_pending(
    plan: list[dict],
    done_ids: set[str],
    limit: int,
    model: str | None,
    prompt: str | None,
    condition: str | None,
) -> list[dict]:
    pending = [row for row in plan if row["validation_id"] not in done_ids]
    if model:
        pending = [row for row in pending if row["source_model_id"] == model]
    if prompt:
        pending = [row for row in pending if row["source_prompt_id"] == prompt]
    if condition:
        pending = [row for row in pending if row["source_condition"] == condition]

    selected: list[dict] = []
    counts = {
        "model": Counter(),
        "prompt": Counter(),
        "condition": Counter(),
        "detector": Counter(),
    }
    for row in plan:
        if row["validation_id"] in done_ids:
            counts["model"][row["source_model_id"]] += 1
            counts["prompt"][row["source_prompt_id"]] += 1
            counts["condition"][row["source_condition"]] += 1
            counts["detector"][str(bool(row["original_detector_label"]))] += 1

    while pending and len(selected) < limit:
        def score(row: dict) -> tuple:
            return (
                counts["model"][row["source_model_id"]],
                counts["prompt"][row["source_prompt_id"]],
                counts["condition"][row["source_condition"]],
                counts["detector"][str(bool(row["original_detector_label"]))],
                row["validation_id"],
            )

        best_i, best = min(enumerate(pending), key=lambda item: score(item[1]))
        selected.append(best)
        pending.pop(best_i)
        counts["model"][best["source_model_id"]] += 1
        counts["prompt"][best["source_prompt_id"]] += 1
        counts["condition"][best["source_condition"]] += 1
        counts["detector"][str(bool(best["original_detector_label"]))] += 1

    return selected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--model")
    parser.add_argument("--prompt")
    parser.add_argument("--condition")
    parser.add_argument("--estimate-only", action="store_true")
    args = parser.parse_args()

    pro = load_pro_runner()
    models = {m.id: m for m in pro.MODELS}
    prompts = {p.id: p for p in pro.MAIN_PROMPTS}
    results_path = args.out_dir / "results.jsonl"
    ledger_path = args.out_dir / "ledger.jsonl"
    existing = load_results(results_path)
    done_ids = {row["validation_id"] for row in existing}
    selected = choose_pending(load_plan(args.plan), done_ids, args.limit, args.model, args.prompt, args.condition)

    print(f"Selected {len(selected)} rows")
    for row in selected:
        print(
            f"  {row['validation_id']} {row['source_model_id']} "
            f"{row['source_prompt_id']} {row['source_condition']} source_trial={row['source_trial']}"
        )
    if args.estimate_only or not selected:
        return

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for idx, row in enumerate(selected, 1):
        model = models[row["source_model_id"]]
        prompt = prompts[row["source_prompt_id"]]
        condition = row["source_condition"]
        started = time.time()
        with tempfile.TemporaryDirectory(prefix=f"full-output-{model.id}-") as tmp:
            work_dir = Path(tmp)
            try:
                raw, meta = pro.call_model(model, prompt, condition, work_dir)
                code = pro.extract_code(raw)
                detector = bool(prompt.detector(code))
                elapsed = time.time() - started
                out = {
                    **row,
                    "rerun_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "rerun_detector_label": detector,
                    "has_code": bool(code.strip()),
                    "code_length": len(code),
                    "code": code,
                    "raw_response": raw,
                    "usage": meta.get("usage") if isinstance(meta, dict) else None,
                    "total_cost_usd": meta.get("total_cost_usd") if isinstance(meta, dict) else None,
                    "elapsed_sec": round(elapsed, 3),
                    "compile_status": "not_run",
                    "compile_detail": "",
                }
                append_jsonl(results_path, out)
                append_jsonl(ledger_path, {
                    "ts": out["rerun_at"],
                    "validation_id": row["validation_id"],
                    "model_id": model.id,
                    "provider": model.provider,
                    "prompt_id": prompt.id,
                    "condition": condition,
                    "status": "ok",
                    "elapsed_sec": out["elapsed_sec"],
                    "rerun_detector_label": detector,
                    "total_cost_usd": out["total_cost_usd"],
                })
                existing.append(out)
                print(f"[{idx}/{len(selected)}] {row['validation_id']} ok detector={detector} len={len(code)}")
            except Exception as exc:
                elapsed = time.time() - started
                append_jsonl(ledger_path, {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "validation_id": row["validation_id"],
                    "model_id": model.id,
                    "provider": model.provider,
                    "prompt_id": prompt.id,
                    "condition": condition,
                    "status": "error",
                    "elapsed_sec": round(elapsed, 3),
                    "error": str(exc)[:500],
                })
                print(f"[{idx}/{len(selected)}] {row['validation_id']} error: {exc}")
        time.sleep(1)

    write_label_template(existing, args.out_dir)
    print(f"Wrote {results_path}")
    print(f"Wrote {args.out_dir / 'labels.csv'}")


if __name__ == "__main__":
    main()
