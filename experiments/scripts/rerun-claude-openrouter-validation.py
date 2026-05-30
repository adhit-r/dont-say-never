#!/usr/bin/env python3
"""
Run a capped Claude-family detector-validation slice through OpenRouter.

This is intentionally separate from the main 2,160-trial replication and from
the Claude CLI validation path. It exists for situations where Claude CLI is
unavailable but a small paid OpenRouter validation slice is acceptable.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = ROOT / "experiments" / "validation" / "detector-validation-sample.jsonl"
OUT_DIR = ROOT / "experiments" / "validation" / "openrouter-claude-reruns"
RESULTS_PATH = OUT_DIR / "detector-validation-openrouter-claude-results.jsonl"
LEDGER_PATH = OUT_DIR / "detector-validation-openrouter-claude-ledger.jsonl"
LABELS_PATH = OUT_DIR / "detector-validation-openrouter-claude-labels.csv"
SUMMARY_PATH = OUT_DIR / "detector-validation-openrouter-claude-summary.md"
PRO_RUNNER_PATH = ROOT / "experiments" / "scripts" / "pro-six-model-replication.py"

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

MODEL_MAP = {
    "claude-opus-4.6": {
        "openrouter_id": "anthropic/claude-opus-4.6",
        "input_per_mtok": 5.0,
        "output_per_mtok": 25.0,
    },
    "claude-sonnet-4.6": {
        "openrouter_id": "anthropic/claude-sonnet-4.6",
        "input_per_mtok": 3.0,
        "output_per_mtok": 15.0,
    },
    "claude-haiku-4.5": {
        "openrouter_id": "anthropic/claude-haiku-4.5",
        "input_per_mtok": 1.0,
        "output_per_mtok": 5.0,
    },
}


def load_pro_runner():
    spec = importlib.util.spec_from_file_location("pro_runner", PRO_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {PRO_RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def load_sample() -> list[dict]:
    with SAMPLE_PATH.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def existing_keys() -> set[str]:
    keys = set()
    if not RESULTS_PATH.exists():
        return keys
    with RESULTS_PATH.open() as f:
        for line in f:
            if line.strip():
                keys.add(json.loads(line)["sample_id"])
    return keys


def choose_rows(rows: list[dict], limit: int, model_filter: str | None) -> list[dict]:
    done = existing_keys()
    pending = [
        row
        for row in rows
        if row["sample_id"] not in done and row["model_id"] in MODEL_MAP
    ]
    if model_filter:
        pending = [row for row in pending if row["model_id"] == model_filter]

    condition_order = {"control": 0, "negative-framing": 1, "positive-framing": 2}
    counts = {"model_id": {}, "prompt_id": {}, "condition": {}, "detector_label": {}}
    selected: list[dict] = []
    while len(selected) < limit and pending:
        def score(row: dict) -> tuple:
            label_key = str(bool(row["detector_label"]))
            return (
                counts["model_id"].get(row["model_id"], 0),
                counts["prompt_id"].get(row["prompt_id"], 0),
                counts["condition"].get(row["condition"], 0),
                counts["detector_label"].get(label_key, 0),
                row["model_id"],
                row["prompt_id"],
                condition_order.get(row["condition"], 99),
                row["trial"],
            )

        idx, row = min(enumerate(pending), key=lambda pair: score(pair[1]))
        selected.append(row)
        pending.pop(idx)
        for key in ("model_id", "prompt_id", "condition"):
            counts[key][row[key]] = counts[key].get(row[key], 0) + 1
        label_key = str(bool(row["detector_label"]))
        counts["detector_label"][label_key] = counts["detector_label"].get(label_key, 0) + 1
    return selected


def estimate_cost(model_id: str, usage: dict | None) -> float | None:
    if not usage:
        return None
    rates = MODEL_MAP[model_id]
    prompt_tokens = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
    completion_tokens = usage.get("completion_tokens") or usage.get("output_tokens") or 0
    return (
        (prompt_tokens / 1_000_000) * rates["input_per_mtok"]
        + (completion_tokens / 1_000_000) * rates["output_per_mtok"]
    )


def prior_cost() -> float:
    total = 0.0
    if not LEDGER_PATH.exists():
        return total
    with LEDGER_PATH.open() as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("status") == "ok" and row.get("estimated_cost_usd") is not None:
                total += float(row["estimated_cost_usd"])
    return total


def call_openrouter(api_key: str, model_id: str, system: str, user_prompt: str) -> tuple[str, dict]:
    payload = {
        "model": MODEL_MAP[model_id]["openrouter_id"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.7,
        "max_tokens": 1200,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OPENROUTER_URL,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/adhit-r/dont-say-never",
            "X-Title": "llm-framing-paper-detector-validation",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter HTTP {exc.code}: {detail[:800]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenRouter request failed: {exc}") from exc

    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError(f"OpenRouter returned no choices: {json.dumps(body)[:800]}")
    message = choices[0].get("message") or {}
    return message.get("content", ""), body


def write_label_template() -> None:
    rows = []
    if RESULTS_PATH.exists():
        with RESULTS_PATH.open() as f:
            rows = [json.loads(line) for line in f if line.strip()]
    fieldnames = [
        "sample_id",
        "rerun_id",
        "model_id",
        "openrouter_model",
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


def write_summary() -> None:
    rows = []
    if RESULTS_PATH.exists():
        with RESULTS_PATH.open() as f:
            rows = [json.loads(line) for line in f if line.strip()]
    total_cost = sum(float(r.get("estimated_cost_usd") or 0.0) for r in rows)
    by_model: dict[str, int] = {}
    by_prompt: dict[str, int] = {}
    for row in rows:
        by_model[row["model_id"]] = by_model.get(row["model_id"], 0) + 1
        by_prompt[row["prompt_id"]] = by_prompt.get(row["prompt_id"], 0) + 1
    lines = [
        "# OpenRouter Claude Validation Reruns",
        "",
        "This artifact is a bounded paid validation lane used only when Claude CLI is unavailable.",
        "It does not mutate the main 2,160-trial dataset.",
        "",
        f"Completed rows: {len(rows)}",
        f"Estimated token cost: ${total_cost:.4f}",
        "",
        "## Rows by Model",
        "",
    ]
    for model, count in sorted(by_model.items()):
        lines.append(f"- `{model}`: {count}")
    lines.extend(["", "## Rows by Prompt", ""])
    for prompt, count in sorted(by_prompt.items()):
        lines.append(f"- `{prompt}`: {count}")
    lines.extend(
        [
            "",
            "## Files",
            "",
            f"- Results: `{RESULTS_PATH.relative_to(ROOT)}`",
            f"- Ledger: `{LEDGER_PATH.relative_to(ROOT)}`",
            f"- Label template: `{LABELS_PATH.relative_to(ROOT)}`",
            "",
        ]
    )
    SUMMARY_PATH.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--model", choices=sorted(MODEL_MAP))
    parser.add_argument("--max-cost-usd", type=float, default=3.0)
    parser.add_argument("--api-key-env", default="OPENROUTER_API_KEY")
    parser.add_argument("--estimate-only", action="store_true")
    args = parser.parse_args()

    api_key = os.environ.get(args.api_key_env)
    if not api_key and not args.estimate_only:
        raise SystemExit(f"Missing {args.api_key_env}. Export it before running paid OpenRouter validation.")

    pro = load_pro_runner()
    prompts = {p.id: p for p in pro.MAIN_PROMPTS}
    rows = choose_rows(load_sample(), args.limit, args.model)
    spent = prior_cost()

    print(f"Selected {len(rows)} OpenRouter Claude validation rows")
    print(f"Existing estimated spend: ${spent:.4f}; cap: ${args.max_cost_usd:.4f}")
    for row in rows:
        print(f"  {row['sample_id']} {row['model_id']} {row['prompt_id']} {row['condition']}")
    if args.estimate_only or not rows:
        return

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for idx, row in enumerate(rows, 1):
        if spent >= args.max_cost_usd:
            print(f"Stopping before row {idx}: spend cap reached (${spent:.4f})")
            break
        prompt = prompts[row["prompt_id"]]
        condition = row["condition"]
        rerun_id = f"{row['sample_id']}-openrouter-{int(time.time())}"
        started = time.time()
        try:
            raw, meta = call_openrouter(
                api_key,
                row["model_id"],
                pro.build_system_prompt(prompt, condition),
                prompt.prompt,
            )
            code = pro.extract_code(raw)
            detector_label = prompt.detector(code)
            cost = estimate_cost(row["model_id"], meta.get("usage"))
            if cost is not None:
                spent += cost
            out = {
                "sample_id": row["sample_id"],
                "rerun_id": rerun_id,
                "model_id": row["model_id"],
                "openrouter_model": MODEL_MAP[row["model_id"]]["openrouter_id"],
                "provider": "openrouter",
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
                "usage": meta.get("usage"),
                "estimated_cost_usd": cost,
                "elapsed_sec": round(time.time() - started, 3),
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
                    "model_id": row["model_id"],
                    "openrouter_model": out["openrouter_model"],
                    "prompt_id": prompt.id,
                    "condition": condition,
                    "status": "ok",
                    "elapsed_sec": out["elapsed_sec"],
                    "rerun_detector_label": detector_label,
                    "usage": out["usage"],
                    "estimated_cost_usd": cost,
                    "cumulative_estimated_cost_usd": spent,
                },
            )
            print(
                f"[{idx}/{len(rows)}] {row['sample_id']} ok "
                f"detector={detector_label} len={len(code)} cost=${cost or 0.0:.4f} total=${spent:.4f}"
            )
        except Exception as exc:
            append_jsonl(
                LEDGER_PATH,
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "sample_id": row["sample_id"],
                    "rerun_id": rerun_id,
                    "model_id": row["model_id"],
                    "openrouter_model": MODEL_MAP[row["model_id"]]["openrouter_id"],
                    "prompt_id": prompt.id,
                    "condition": condition,
                    "status": "error",
                    "elapsed_sec": round(time.time() - started, 3),
                    "error": str(exc)[:800],
                    "cumulative_estimated_cost_usd": spent,
                },
            )
            print(f"[{idx}/{len(rows)}] {row['sample_id']} error: {exc}")
        time.sleep(1)

    write_label_template()
    write_summary()
    print(f"Wrote {RESULTS_PATH}")
    print(f"Wrote {LABELS_PATH}")
    print(f"Wrote {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
