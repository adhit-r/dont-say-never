#!/usr/bin/env python3
"""Run Claude-family strengthening suites through OpenRouter with a hard cost cap."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRO_RUNNER_PATH = ROOT / "experiments" / "scripts" / "pro-six-model-replication.py"
OUT_DIR = ROOT / "experiments" / "data" / "pro-replication"
LEDGER_PATH = OUT_DIR / "openrouter-claude-ledger.jsonl"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

TRIALS_PER_CELL = 20
INTER_TRIAL_SEC = 1
INTER_CELL_SEC = 3

MODEL_MAP = {
    "claude-opus-4.6": {
        "name": "Claude Opus 4.6",
        "openrouter_id": "anthropic/claude-opus-4.6",
        "input_per_mtok": 5.0,
        "output_per_mtok": 25.0,
    },
    "claude-sonnet-4.6": {
        "name": "Claude Sonnet 4.6",
        "openrouter_id": "anthropic/claude-sonnet-4.6",
        "input_per_mtok": 3.0,
        "output_per_mtok": 15.0,
    },
    "claude-haiku-4.5": {
        "name": "Claude Haiku 4.5",
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


def output_path(suite: str, model_id: str) -> Path:
    return OUT_DIR / suite / f"{model_id}.json"


def load_results(suite: str, model_id: str) -> list[dict]:
    path = output_path(suite, model_id)
    if not path.exists():
        return []
    with path.open() as f:
        return json.load(f).get("results", [])


def save_results(pro, suite: str, model_id: str, results: list[dict], status: str) -> None:
    meta = MODEL_MAP[model_id]
    path = output_path(suite, model_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": {
            "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "suite": suite,
            "model_id": model_id,
            "model_name": meta["name"],
            "provider": "openrouter",
            "openrouter_model": meta["openrouter_id"],
            "route_note": "Claude CLI unavailable; this strengthening suite uses OpenRouter with a hard cost cap. Main-suite Claude results remain Claude CLI provenance.",
            "trials_per_cell": TRIALS_PER_CELL,
            "conditions": pro.CONDITIONS_BY_SUITE[suite],
            "prompts": len(pro.PROMPTS_BY_SUITE[suite]),
            "status": status,
        },
        "summary": pro.build_summary(results),
        "results": results,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(payload, f, indent=2)
    tmp.replace(path)


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


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


def prior_cost(suite: str) -> float:
    if not LEDGER_PATH.exists():
        return 0.0
    total = 0.0
    with LEDGER_PATH.open() as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("suite") == suite and row.get("status") == "ok":
                total += float(row.get("estimated_cost_usd") or 0.0)
    return total


def call_openrouter(api_key: str, model_id: str, system: str, user_prompt: str, max_tokens: int) -> tuple[str, dict]:
    payload = {
        "model": MODEL_MAP[model_id]["openrouter_id"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.7,
        "max_tokens": max_tokens,
    }
    req = urllib.request.Request(
        OPENROUTER_URL,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/adhit-r/dont-say-never",
            "X-Title": "llm-framing-paper-openrouter-claude-suite",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter HTTP {exc.code}: {detail[:800]}") from exc
    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError(f"OpenRouter returned no choices: {json.dumps(body)[:800]}")
    return choices[0].get("message", {}).get("content", ""), body


def valid_count(results: list[dict], prompt_id: str, condition: str) -> int:
    return sum(
        1
        for row in results
        if row["prompt_id"] == prompt_id and row["condition"] == condition and not row.get("error")
    )


def next_cells(pro, suite: str, results: list[dict]) -> list[tuple[object, str]]:
    cells = []
    for prompt in pro.PROMPTS_BY_SUITE[suite]:
        for condition in pro.CONDITIONS_BY_SUITE[suite]:
            if valid_count(results, prompt.id, condition) < TRIALS_PER_CELL:
                cells.append((prompt, condition))
    return cells


def run_cell(
    pro,
    api_key: str,
    suite: str,
    model_id: str,
    prompt,
    condition: str,
    results: list[dict],
    spent: float,
    max_cost: float,
    max_tokens: int,
) -> float:
    done = valid_count(results, prompt.id, condition)
    print(f"{suite:10s} {model_id:20s} {prompt.id:18s} {condition:18s} ", end="", flush=True)
    while done < TRIALS_PER_CELL:
        if spent >= max_cost:
            raise RuntimeError(f"OpenRouter cost cap reached: ${spent:.4f} >= ${max_cost:.4f}")
        started = time.time()
        try:
            raw, meta = call_openrouter(api_key, model_id, pro.build_system_prompt(prompt, condition), prompt.prompt, max_tokens)
            code = pro.extract_code(raw)
            vuln = prompt.detector(code)
            cost = estimate_cost(model_id, meta.get("usage"))
            if cost is not None:
                spent += cost
            row = {
                "model_id": model_id,
                "model_name": MODEL_MAP[model_id]["name"],
                "provider": "openrouter",
                "openrouter_model": MODEL_MAP[model_id]["openrouter_id"],
                "repo": prompt.repo,
                "prompt_id": prompt.id,
                "cwe": prompt.cwe,
                "language": prompt.language,
                "label": prompt.label,
                "condition": condition,
                "trial": done,
                "vulnerable": vuln,
                "code_length": len(code),
                "code": code,
                "code_preview": code[:300],
                "raw_response": raw,
                "usage": meta.get("usage"),
                "estimated_cost_usd": cost,
                "max_tokens": max_tokens,
            }
            results.append(row)
            append_jsonl(
                LEDGER_PATH,
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "suite": suite,
                    "model_id": model_id,
                    "openrouter_model": MODEL_MAP[model_id]["openrouter_id"],
                    "prompt_id": prompt.id,
                    "condition": condition,
                    "trial": done,
                    "status": "ok",
                    "vulnerable": vuln,
                    "elapsed_sec": round(time.time() - started, 3),
                    "estimated_cost_usd": cost,
                    "max_tokens": max_tokens,
                    "cumulative_estimated_cost_usd": spent,
                },
            )
            save_results(pro, suite, model_id, results, "in-progress")
            print("V" if vuln else "S", end="", flush=True)
            done += 1
        except Exception as exc:
            append_jsonl(
                LEDGER_PATH,
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "suite": suite,
                    "model_id": model_id,
                    "openrouter_model": MODEL_MAP[model_id]["openrouter_id"],
                    "prompt_id": prompt.id,
                    "condition": condition,
                    "trial": done,
                    "status": "error",
                    "elapsed_sec": round(time.time() - started, 3),
                    "error": str(exc)[:800],
                    "max_tokens": max_tokens,
                    "cumulative_estimated_cost_usd": spent,
                },
            )
            print("E", end="", flush=True)
            time.sleep(5)
        time.sleep(INTER_TRIAL_SEC)
    print(f" ${spent:.4f}")
    time.sleep(INTER_CELL_SEC)
    return spent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=["non-api", "four-arm-addons", "cross-language"], default="non-api")
    parser.add_argument("--model", choices=sorted(MODEL_MAP))
    parser.add_argument("--cells-per-run", type=int, default=1)
    parser.add_argument("--max-cost-usd", type=float, default=3.0)
    parser.add_argument("--max-tokens", type=int, default=1200)
    parser.add_argument("--api-key-env", default="OPENROUTER_API_KEY")
    parser.add_argument("--estimate-only", action="store_true")
    args = parser.parse_args()

    api_key = os.environ.get(args.api_key_env)
    if not api_key and not args.estimate_only:
        raise SystemExit(f"Missing {args.api_key_env}. Export it before running paid OpenRouter suite.")

    pro = load_pro_runner()
    model_ids = [args.model] if args.model else list(MODEL_MAP)
    selected = []
    for model_id in model_ids:
        results = load_results(args.suite, model_id)
        cells = next_cells(pro, args.suite, results)
        if cells:
            selected.append((model_id, cells[0]))
        if len(selected) >= args.cells_per_run:
            break

    print(f"Selected {len(selected)} cells for {args.suite}; prior suite cost=${prior_cost(args.suite):.4f}; cap=${args.max_cost_usd:.4f}")
    for model_id, (prompt, condition) in selected:
        done = valid_count(load_results(args.suite, model_id), prompt.id, condition)
        print(f"  {model_id} {prompt.id} {condition} done={done}/{TRIALS_PER_CELL}")
    if args.estimate_only or not selected:
        return

    spent = prior_cost(args.suite)
    for model_id, (prompt, condition) in selected:
        results = load_results(args.suite, model_id)
        spent = run_cell(
            pro,
            api_key,
            args.suite,
            model_id,
            prompt,
            condition,
            results,
            spent,
            args.max_cost_usd,
            args.max_tokens,
        )

    for model_id in model_ids:
        results = load_results(args.suite, model_id)
        status = "completed" if not next_cells(pro, args.suite, results) else "in-progress"
        if results:
            save_results(pro, args.suite, model_id, results, status)


if __name__ == "__main__":
    main()
