#!/usr/bin/env python3
"""
Rerun a bounded subset of detector-validation rows and preserve full generated
code for manual security labeling.

This does not mutate the final 2,160-trial dataset. It creates a fresh
validation artifact under experiments/validation/reruns/.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = ROOT / "experiments" / "validation" / "detector-validation-sample.jsonl"
OUT_DIR = ROOT / "experiments" / "validation" / "reruns"
RESULTS_PATH = OUT_DIR / "detector-validation-rerun-results.jsonl"
LEDGER_PATH = OUT_DIR / "detector-validation-rerun-ledger.jsonl"
LABELS_PATH = OUT_DIR / "detector-validation-rerun-labels.csv"
PRO_RUNNER_PATH = ROOT / "experiments" / "scripts" / "pro-six-model-replication.py"


def load_pro_runner():
    spec = importlib.util.spec_from_file_location("pro_runner", PRO_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {PRO_RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_sample() -> list[dict]:
    rows = []
    with SAMPLE_PATH.open() as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def existing_keys() -> set[str]:
    keys = set()
    if not RESULTS_PATH.exists():
        return keys
    with RESULTS_PATH.open() as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            keys.add(row["sample_id"])
    return keys


def choose_rows(rows: list[dict], limit: int, model_filter: str | None, prompt_filter: str | None) -> list[dict]:
    done = existing_keys()
    pending = [r for r in rows if r["sample_id"] not in done]
    if model_filter:
        pending = [r for r in pending if r["model_id"] == model_filter]
    if prompt_filter:
        pending = [r for r in pending if r["prompt_id"] == prompt_filter]

    condition_order = {"control": 0, "negative-framing": 1, "positive-framing": 2}
    pending.sort(key=lambda r: (r["prompt_id"], r["model_id"], condition_order.get(r["condition"], 99), r["trial"]))
    counts = {
        "prompt_id": {},
        "model_id": {},
        "condition": {},
        "detector_label": {},
    }
    selected: list[dict] = []
    while len(selected) < limit and pending:
        def score(row: dict) -> tuple:
            label_key = str(bool(row["detector_label"]))
            return (
                counts["prompt_id"].get(row["prompt_id"], 0),
                counts["model_id"].get(row["model_id"], 0),
                counts["condition"].get(row["condition"], 0),
                counts["detector_label"].get(label_key, 0),
                row["prompt_id"],
                row["model_id"],
                condition_order.get(row["condition"], 99),
                row["trial"],
            )

        best_idx, best = min(enumerate(pending), key=lambda pair: score(pair[1]))
        selected.append(best)
        pending.pop(best_idx)
        for key in ("prompt_id", "model_id", "condition"):
            counts[key][best[key]] = counts[key].get(best[key], 0) + 1
        label_key = str(bool(best["detector_label"]))
        counts["detector_label"][label_key] = counts["detector_label"].get(label_key, 0) + 1
    return selected


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def write_label_template() -> None:
    rows = []
    if RESULTS_PATH.exists():
        with RESULTS_PATH.open() as f:
            rows = [json.loads(line) for line in f if line.strip()]
    fieldnames = [
        "sample_id",
        "rerun_id",
        "model_id",
        "prompt_id",
        "cwe",
        "condition",
        "original_trial",
        "original_detector_label",
        "rerun_detector_label",
        "code_length",
        "manual_label",
        "manual_confidence",
        "manual_notes",
    ]
    with LABELS_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=18, help="Maximum new rows to rerun")
    parser.add_argument("--model", help="Optional model_id filter")
    parser.add_argument("--prompt", help="Optional prompt_id filter")
    parser.add_argument("--estimate-only", action="store_true", help="Print planned rows without model calls")
    args = parser.parse_args()

    pro = load_pro_runner()
    prompts = {p.id: p for p in pro.MAIN_PROMPTS}
    models = {m.id: m for m in pro.MODELS}
    rows = choose_rows(load_sample(), args.limit, args.model, args.prompt)

    print(f"Selected {len(rows)} validation rerun rows")
    for row in rows:
        print(f"  {row['sample_id']} {row['model_id']} {row['prompt_id']} {row['condition']} trial={row['trial']}")
    if args.estimate_only or not rows:
        return

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for idx, row in enumerate(rows, 1):
        model = models[row["model_id"]]
        prompt = prompts[row["prompt_id"]]
        condition = row["condition"]
        rerun_id = f"{row['sample_id']}-rerun-{int(time.time())}"
        started = time.time()
        with tempfile.TemporaryDirectory(prefix=f"detector-validation-{model.id}-") as tmp:
            work_dir = Path(tmp)
            try:
                raw, meta = pro.call_model(model, prompt, condition, work_dir)
                code = pro.extract_code(raw)
                detector_label = prompt.detector(code)
                elapsed = time.time() - started
                out = {
                    "sample_id": row["sample_id"],
                    "rerun_id": rerun_id,
                    "model_id": model.id,
                    "model_name": model.name,
                    "provider": model.provider,
                    "prompt_id": prompt.id,
                    "cwe": prompt.cwe,
                    "language": prompt.language,
                    "condition": condition,
                    "original_trial": row["trial"],
                    "original_detector_label": row["detector_label"],
                    "rerun_detector_label": detector_label,
                    "code_length": len(code),
                    "code": code,
                    "raw_response": raw,
                    "usage": meta.get("usage") if isinstance(meta, dict) else None,
                    "total_cost_usd": meta.get("total_cost_usd") if isinstance(meta, dict) else None,
                    "elapsed_sec": round(elapsed, 3),
                    "manual_label": "",
                    "manual_confidence": "",
                    "manual_notes": "",
                }
                append_jsonl(RESULTS_PATH, out)
                append_jsonl(
                    LEDGER_PATH,
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "sample_id": row["sample_id"],
                        "rerun_id": rerun_id,
                        "model_id": model.id,
                        "provider": model.provider,
                        "prompt_id": prompt.id,
                        "condition": condition,
                        "status": "ok",
                        "elapsed_sec": round(elapsed, 3),
                        "rerun_detector_label": detector_label,
                        "total_cost_usd": out["total_cost_usd"],
                        "usage": out["usage"],
                    },
                )
                print(f"[{idx}/{len(rows)}] {row['sample_id']} ok detector={detector_label} len={len(code)}")
            except Exception as exc:
                elapsed = time.time() - started
                append_jsonl(
                    LEDGER_PATH,
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "sample_id": row["sample_id"],
                        "rerun_id": rerun_id,
                        "model_id": model.id,
                        "provider": model.provider,
                        "prompt_id": prompt.id,
                        "condition": condition,
                        "status": "error",
                        "elapsed_sec": round(elapsed, 3),
                        "error": str(exc)[:500],
                    },
                )
                print(f"[{idx}/{len(rows)}] {row['sample_id']} error: {exc}")
        time.sleep(1)

    write_label_template()
    print(f"Wrote {RESULTS_PATH}")
    print(f"Wrote {LABELS_PATH}")


if __name__ == "__main__":
    main()
