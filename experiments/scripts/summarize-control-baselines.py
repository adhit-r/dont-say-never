#!/usr/bin/env python3
"""Summarize the neutral/generic-control extension.

This extension addresses the reviewer concern that the original `control`
condition was an adversarial fast-prototyping baseline because it discouraged
extra validation or security measures. The summary compares that original
control against two new controls and the strongest targeted-rule arm.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[2]
MAIN_DIR = ROOT / "experiments" / "data" / "pro-replication" / "main"
BASELINE_DIR = ROOT / "experiments" / "data" / "pro-replication" / "control-baselines"
FOUR_ARM_DIR = ROOT / "experiments" / "data" / "pro-replication" / "four-arm-addons"
OUT_MD = ROOT / "experiments" / "analysis" / "control-baselines-summary.md"
OUT_FIG = ROOT / "figures" / "fig-control-baselines.png"

MODELS = [
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.3-codex",
    "claude-opus-4.6",
    "claude-sonnet-4.6",
    "claude-haiku-4.5",
]
PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]
CONDITIONS = [
    "fast-prototype-control",
    "neutral-control",
    "generic-security-control",
    "targeted-combined-rule",
]


def load_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text()).get("results", [])


def collect() -> dict[tuple[str, str, str], dict[str, int]]:
    cells: dict[tuple[str, str, str], dict[str, int]] = defaultdict(lambda: {"vuln": 0, "total": 0, "errors": 0})
    for model in MODELS:
        for row in load_rows(MAIN_DIR / f"{model}.json"):
            if row.get("condition") != "control":
                continue
            key = (model, row["prompt_id"], "fast-prototype-control")
            add_row(cells[key], row)
        for row in load_rows(BASELINE_DIR / f"{model}.json"):
            if row.get("condition") not in {"neutral-control", "generic-security-control"}:
                continue
            key = (model, row["prompt_id"], row["condition"])
            add_row(cells[key], row)
        for row in load_rows(FOUR_ARM_DIR / f"{model}.json"):
            if row.get("condition") != "combined":
                continue
            key = (model, row["prompt_id"], "targeted-combined-rule")
            add_row(cells[key], row)
    return cells


def add_row(cell: dict[str, int], row: dict) -> None:
    if row.get("error"):
        cell["errors"] += 1
        return
    cell["total"] += 1
    cell["vuln"] += int(bool(row.get("vulnerable")))


def pct(vuln: int, total: int) -> float:
    return 100.0 * vuln / total if total else 0.0


def aggregate(cells: dict[tuple[str, str, str], dict[str, int]], models: list[str]) -> dict[str, dict[str, int]]:
    out = {condition: {"vuln": 0, "total": 0, "errors": 0} for condition in CONDITIONS}
    for model in models:
        for prompt in PROMPTS:
            for condition in CONDITIONS:
                cell = cells.get((model, prompt, condition), {"vuln": 0, "total": 0, "errors": 0})
                out[condition]["vuln"] += cell["vuln"]
                out[condition]["total"] += cell["total"]
                out[condition]["errors"] += cell["errors"]
    return out


def make_figure(cells: dict[tuple[str, str, str], dict[str, int]]) -> None:
    groups = {
        "All models": MODELS,
        "GPT family": ["gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex"],
        "Claude family": ["claude-opus-4.6", "claude-sonnet-4.6", "claude-haiku-4.5"],
    }
    labels = ["Fast prototype", "Neutral", "Generic secure", "Targeted CWE rule"]
    colors = ["#8A8F98", "#4B75A8", "#D28E34", "#2F6B4F"]

    fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.6), sharey=True)
    for ax, (title, models) in zip(axes, groups.items()):
        agg = aggregate(cells, models)
        values = [pct(agg[condition]["vuln"], agg[condition]["total"]) for condition in CONDITIONS]
        totals = [agg[condition]["total"] for condition in CONDITIONS]
        ax.bar(range(len(CONDITIONS)), values, color=colors, width=0.72)
        for idx, (value, total) in enumerate(zip(values, totals)):
            label = f"{value:.1f}%" if total else "pending"
            ax.text(idx, value + 2.0, label, ha="center", va="bottom", fontsize=8)
        ax.set_title(title)
        ax.set_xticks(range(len(CONDITIONS)))
        ax.set_xticklabels(labels, rotation=28, ha="right")
        ax.set_ylim(0, 100)
        ax.grid(axis="y", alpha=0.25)
    axes[0].set_ylabel("Vulnerable outputs (%)")
    fig.suptitle("Control-baseline extension: is the original control too adversarial?", y=1.02)
    fig.tight_layout()
    OUT_FIG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_FIG, dpi=220, bbox_inches="tight")
    plt.close(fig)


def make_markdown(cells: dict[tuple[str, str, str], dict[str, int]]) -> str:
    lines = [
        "# Control-Baseline Extension Summary",
        "",
        "This extension addresses the reviewer critique that the original main-suite control was not neutral.",
        "",
        "Compared conditions:",
        "",
        "- `fast-prototype-control`: reused original main-suite control, which says not to add extra validation/security unless asked.",
        "- `neutral-control`: new control, helpful coding assistant with no security discouragement.",
        "- `generic-security-control`: new control, broad secure-coding instruction but no CWE-specific rule.",
        "- `targeted-combined-rule`: reused four-arm `combined` condition with a concrete CWE-specific prohibition and safe replacement.",
        "",
        "## Coverage By Model",
        "",
        "| Model | Fast prototype | Neutral | Generic secure | Targeted CWE rule | Errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for model in MODELS:
        cells_for_model = aggregate(cells, [model])
        parts = []
        errors = 0
        for condition in CONDITIONS:
            cell = cells_for_model[condition]
            parts.append(f"{cell['vuln']}/{cell['total']}")
            errors += cell["errors"]
        lines.append(f"| `{model}` | " + " | ".join(parts) + f" | {errors} |")

    lines += [
        "",
        "## Aggregate",
        "",
        "| Stack | Condition | Vulnerable | Total | Rate |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for stack, models in {
        "All models": MODELS,
        "GPT family": ["gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex"],
        "Claude family": ["claude-opus-4.6", "claude-sonnet-4.6", "claude-haiku-4.5"],
    }.items():
        cells_for_stack = aggregate(cells, models)
        for condition in CONDITIONS:
            cell = cells_for_stack[condition]
            rate = f"{pct(cell['vuln'], cell['total']):.1f}%" if cell["total"] else "pending"
            lines.append(f"| {stack} | {condition} | {cell['vuln']} | {cell['total']} | {rate} |")

    lines += [
        "",
        "## Interpretation Template",
        "",
        "Use this extension to separate three effects:",
        "",
        "1. Whether the original control inflated vulnerability by discouraging security.",
        "2. Whether generic secure-coding advice helps without CWE-specific rules.",
        "3. Whether targeted CWE-specific persistent rules outperform generic security advice.",
        "",
        f"Figure: `{OUT_FIG.relative_to(ROOT)}`",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    cells = collect()
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(make_markdown(cells))
    make_figure(cells)
    print(f"Wrote {OUT_MD}")
    print(f"Wrote {OUT_FIG}")


if __name__ == "__main__":
    main()
