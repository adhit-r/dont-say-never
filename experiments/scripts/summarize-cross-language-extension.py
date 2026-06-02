#!/usr/bin/env python3
"""Summarize the cross-language extension."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "experiments" / "data" / "pro-replication" / "cross-language"
OUT = ROOT / "experiments" / "analysis" / "cross-language-extension-summary.md"

MODELS = [
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.3-codex",
    "claude-opus-4.6",
    "claude-sonnet-4.6",
    "claude-haiku-4.5",
]
PROMPTS = ["py-exec-dynamic", "py-md5-hash", "py-insecure-random", "go-exec-cmd"]
CONDITIONS = ["control", "negative-framing", "positive-framing"]


def load(model: str) -> list[dict]:
    path = DATA / f"{model}.json"
    if not path.exists():
        return []
    return json.loads(path.read_text()).get("results", [])


def cell(rows: list[dict], condition: str | None = None, prompt: str | None = None) -> tuple[int, int, int]:
    selected = [
        r for r in rows
        if (condition is None or r.get("condition") == condition)
        and (prompt is None or r.get("prompt_id") == prompt)
    ]
    valid = [r for r in selected if not r.get("error")]
    return sum(1 for r in valid if r.get("vulnerable")), len(valid), sum(1 for r in selected if r.get("error"))


def pct(v: int, n: int) -> str:
    return f"{100 * v / n:.1f}%" if n else "n/a"


def main() -> None:
    lines = [
        "# Cross-Language Extension Summary",
        "",
        "The cross-language extension tests Python and Go prompts using the same condition structure as the main replication.",
        "GPT-5.3 Codex failed the first cross-language cell after three Codex route errors and is excluded from cross-language conclusions.",
        "",
        "## Coverage",
        "",
        "| Model | Valid | Errors | Vulnerable | Rate |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    included = []
    for model in MODELS:
        rows = load(model)
        v, n, e = cell(rows)
        if n:
            included.append(model)
        lines.append(f"| `{model}` | {n}/240 | {e} | {v} | {pct(v, n)} |")

    lines += [
        "",
        "## Aggregate By Condition, Completed Models Only",
        "",
        "| Condition | Vulnerable | Total | Rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for condition in CONDITIONS:
        vuln = total = 0
        for model in included:
            v, n, _ = cell(load(model), condition=condition)
            vuln += v
            total += n
        lines.append(f"| {condition} | {vuln} | {total} | {pct(vuln, total)} |")

    lines += [
        "",
        "## Aggregate By Prompt, Completed Models Only",
        "",
        "| Prompt | Vulnerable | Total | Rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for prompt in PROMPTS:
        vuln = total = 0
        for model in included:
            v, n, _ = cell(load(model), prompt=prompt)
            vuln += v
            total += n
        lines.append(f"| {prompt} | {vuln} | {total} | {pct(vuln, total)} |")

    lines += [
        "",
        "## Interpretation",
        "",
        "- Cross-language evidence is directional, not final, because one GPT-family model failed the Codex route.",
        "- Rule injection remains useful in Python dynamic-execution and Go shell-command cells.",
        "- Python MD5 and insecure-random results expose a language-rule limitation: the current rules are still partly JavaScript-oriented, so this extension should be interpreted as a stress test of portability rather than a final language-specific secure-coding benchmark.",
        "- A stronger cross-language paper version should use language-specific negative and positive rule text.",
        "",
        "Figure: `figures/fig-pro-cross-language.png`",
        "",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
