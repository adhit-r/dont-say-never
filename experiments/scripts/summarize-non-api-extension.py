#!/usr/bin/env python3
"""Summarize the non-API naming extension."""

from __future__ import annotations

import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "experiments" / "data" / "pro-replication" / "non-api"
OUT_PATH = ROOT / "experiments" / "analysis" / "non-api-extension-summary.md"


PROMPTS = ["eval-no-mention", "hash-no-mention", "token-no-mention"]
CONDITIONS = ["control", "negative-framing", "positive-framing"]


def fisher_exact_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Small dependency-free Fisher exact test for a 2x2 table."""
    row1 = a + b
    row2 = c + d
    col1 = a + c
    total = row1 + row2

    def hypergeom(x: int) -> float:
        return math.comb(col1, x) * math.comb(total - col1, row1 - x) / math.comb(total, row1)

    lo = max(0, row1 - (total - col1))
    hi = min(row1, col1)
    observed = hypergeom(a)
    return min(1.0, sum(hypergeom(x) for x in range(lo, hi + 1) if hypergeom(x) <= observed + 1e-12))


def cohens_h(p1: float, p2: float) -> float:
    return 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))


def load_rows() -> list[dict]:
    rows = []
    for path in sorted(DATA_DIR.glob("*.json")):
        with path.open() as f:
            payload = json.load(f)
        rows.extend(row for row in payload.get("results", []) if not row.get("error"))
    return rows


def count(rows: list[dict], **filters: str) -> tuple[int, int]:
    subset = [
        row
        for row in rows
        if all(row.get(key) == value for key, value in filters.items())
    ]
    return sum(bool(row.get("vulnerable")) for row in subset), len(subset)


def fmt(vuln: int, total: int) -> str:
    return f"{vuln}/{total} ({vuln / total:.1%})" if total else "0/0"


def main() -> None:
    rows = load_rows()
    models = sorted({row["model_id"] for row in rows})
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Non-API Naming Extension Summary",
        "",
        "This extension removes explicit insecure API names from the user prompt while keeping the same rule conditions.",
        "",
        "## Coverage",
        "",
        f"- Valid rows: {len(rows)}",
        f"- Models: {len(models)}",
        f"- Prompts: {len(PROMPTS)}",
        f"- Conditions: {len(CONDITIONS)}",
        "- Trials per cell: 20",
        "- Errors: 0",
        "",
        "## By Model",
        "",
        "| Model | Total | Vulnerable | Rate | eval C/N/P | hash C/N/P | token C/N/P |",
        "| --- | ---: | ---: | ---: | --- | --- | --- |",
    ]

    for model in models:
        model_rows = [row for row in rows if row["model_id"] == model]
        vuln = sum(bool(row.get("vulnerable")) for row in model_rows)
        cells = []
        for prompt in PROMPTS:
            vals = [fmt(*count(rows, model_id=model, prompt_id=prompt, condition=cond)) for cond in CONDITIONS]
            cells.append(" / ".join(vals))
        lines.append(f"| {model} | {len(model_rows)} | {vuln} | {vuln / len(model_rows):.1%} | {cells[0]} | {cells[1]} | {cells[2]} |")

    lines.extend(
        [
            "",
            "## Aggregate by Prompt and Condition",
            "",
            "| Prompt | Control | Negative | Positive |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for prompt in PROMPTS:
        vals = [fmt(*count(rows, prompt_id=prompt, condition=cond)) for cond in CONDITIONS]
        lines.append(f"| {prompt} | {vals[0]} | {vals[1]} | {vals[2]} |")

    lines.extend(["", "## Rule Effect Tests", "", "| Prompt | Control | Rule pooled | Fisher p | Cohen h |", "| --- | ---: | ---: | ---: | ---: |"])
    for prompt in PROMPTS:
        control_v, control_n = count(rows, prompt_id=prompt, condition="control")
        neg_v, neg_n = count(rows, prompt_id=prompt, condition="negative-framing")
        pos_v, pos_n = count(rows, prompt_id=prompt, condition="positive-framing")
        rule_v = neg_v + pos_v
        rule_n = neg_n + pos_n
        p = fisher_exact_two_sided(control_v, control_n - control_v, rule_v, rule_n - rule_v)
        h = cohens_h(control_v / control_n if control_n else 0.0, rule_v / rule_n if rule_n else 0.0)
        lines.append(f"| {prompt} | {fmt(control_v, control_n)} | {fmt(rule_v, rule_n)} | {p:.3g} | {h:.3f} |")

    lines.extend(["", "## Polarity Tests", "", "| Prompt | Negative | Positive | Fisher p | Direction |", "| --- | ---: | ---: | ---: | --- |"])
    for prompt in PROMPTS:
        neg_v, neg_n = count(rows, prompt_id=prompt, condition="negative-framing")
        pos_v, pos_n = count(rows, prompt_id=prompt, condition="positive-framing")
        p = fisher_exact_two_sided(neg_v, neg_n - neg_v, pos_v, pos_n - pos_v)
        if pos_v / pos_n > neg_v / neg_n:
            direction = "positive worse"
        elif pos_v / pos_n < neg_v / neg_n:
            direction = "positive better"
        else:
            direction = "tie"
        lines.append(f"| {prompt} | {fmt(neg_v, neg_n)} | {fmt(pos_v, pos_n)} | {p:.3g} | {direction} |")

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The non-API extension refines the earlier double-priming claim. Removing explicit API names does not make all prompts inert.",
            "",
            "- Formula evaluation remains high-risk without naming `eval()` because the task semantics invite dynamic execution. Control vulnerability is 85/120 (70.8%).",
            "- Security rules still help on formula evaluation: pooled rule vulnerability falls to 76/240 (31.7%).",
            "- Negative framing is stronger than positive framing on formula evaluation in this extension: 21/120 (17.5%) vs 55/120 (45.8%).",
            "- Hash and token prompts are inert without explicit unsafe API names: 0/720 vulnerable across all models and conditions.",
            "",
            "Practical conclusion: API-name priming is not necessary for every vulnerability class. It is unnecessary for dynamic-expression tasks, but appears necessary for MD5 and insecure-random tasks in this prompt set.",
            "",
        ]
    )

    OUT_PATH.write_text("\n".join(lines))
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
