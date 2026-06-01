#!/usr/bin/env python3
"""Summarize the four-arm add-on extension.

The four-arm suite reuses the main-suite control condition and adds three
conditions: pure-negative, pure-positive, and combined. Claude rows may be
partial when OpenRouter credits are exhausted; this script marks coverage
explicitly instead of pretending the extension is complete.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[2]
MAIN_DIR = ROOT / "experiments" / "data" / "pro-replication" / "main"
ADDON_DIR = ROOT / "experiments" / "data" / "pro-replication" / "four-arm-addons"
OUT_MD = ROOT / "experiments" / "analysis" / "four-arm-extension-summary.md"
OUT_FIG = ROOT / "figures" / "fig-four-arm-decomposition-partial.png"
PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]
CONDITIONS = ["control", "pure-negative", "pure-positive", "combined"]
MODELS = [
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.3-codex",
    "claude-opus-4.6",
    "claude-sonnet-4.6",
    "claude-haiku-4.5",
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
            key = (model, row["prompt_id"], "control")
            if row.get("error"):
                cells[key]["errors"] += 1
                continue
            cells[key]["total"] += 1
            cells[key]["vuln"] += int(bool(row.get("vulnerable")))
        for row in load_rows(ADDON_DIR / f"{model}.json"):
            key = (model, row["prompt_id"], row["condition"])
            if row.get("error"):
                cells[key]["errors"] += 1
                continue
            cells[key]["total"] += 1
            cells[key]["vuln"] += int(bool(row.get("vulnerable")))
    return cells


def aggregate_by_condition(cells: dict[tuple[str, str, str], dict[str, int]], models: list[str]) -> dict[str, dict[str, int]]:
    agg = {condition: {"vuln": 0, "total": 0, "errors": 0} for condition in CONDITIONS}
    for model in models:
        for prompt in PROMPTS:
            for condition in CONDITIONS:
                cell = cells.get((model, prompt, condition), {"vuln": 0, "total": 0, "errors": 0})
                agg[condition]["vuln"] += cell["vuln"]
                agg[condition]["total"] += cell["total"]
                agg[condition]["errors"] += cell["errors"]
    return agg


def pct(vuln: int, total: int) -> float:
    return 100.0 * vuln / total if total else 0.0


def make_figure(cells: dict[tuple[str, str, str], dict[str, int]]) -> None:
    groups = {
        "GPT complete": ["gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex"],
        "Claude partial": ["claude-opus-4.6", "claude-sonnet-4.6", "claude-haiku-4.5"],
    }
    labels = CONDITIONS
    x = list(range(len(labels)))
    width = 0.34

    fig, ax = plt.subplots(figsize=(9.5, 5.2))
    colors = ["#2F6B4F", "#B44B34"]
    for idx, (name, models) in enumerate(groups.items()):
        agg = aggregate_by_condition(cells, models)
        values = [pct(agg[c]["vuln"], agg[c]["total"]) for c in labels]
        offsets = [i + (idx - 0.5) * width for i in x]
        ax.bar(offsets, values, width=width, label=name, color=colors[idx])
        for ox, value, condition in zip(offsets, values, labels):
            total = agg[condition]["total"]
            ax.text(ox, value + 1.2, f"{value:.1f}%\n(n={total})", ha="center", va="bottom", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(["Control", "Pure negative", "Pure positive", "Combined"])
    ax.set_ylabel("Vulnerable outputs (%)")
    ax.set_title("Four-arm decomposition: control reused, add-on rows partial for Claude")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    fig.tight_layout()
    OUT_FIG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT_FIG, dpi=220)
    plt.close(fig)


def make_markdown(cells: dict[tuple[str, str, str], dict[str, int]]) -> str:
    lines = [
        "# Four-Arm Extension Summary",
        "",
        "This summary merges the main-suite `control` rows with the `four-arm-addons` rows.",
        "GPT-family add-on rows are complete. Claude-family add-on rows are partial because the OpenRouter key hit a hard 402 credit/max-token limit.",
        "",
        "## Coverage",
        "",
        "| Model | Control | Pure negative | Pure positive | Combined | Add-on errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for model in MODELS:
        row = []
        errors = 0
        for condition in CONDITIONS:
            total = sum(cells.get((model, prompt, condition), {"total": 0})["total"] for prompt in PROMPTS)
            vuln = sum(cells.get((model, prompt, condition), {"vuln": 0})["vuln"] for prompt in PROMPTS)
            row.append(f"{vuln}/{total}")
            errors += sum(cells.get((model, prompt, condition), {"errors": 0})["errors"] for prompt in PROMPTS)
        lines.append(f"| `{model}` | " + " | ".join(row) + f" | {errors} |")

    lines += ["", "## Aggregate By Provider Stack", "", "| Stack | Condition | Vulnerable | Total | Rate |", "| --- | --- | ---: | ---: | ---: |"]
    for stack, models in {
        "GPT complete": ["gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex"],
        "Claude partial": ["claude-opus-4.6", "claude-sonnet-4.6", "claude-haiku-4.5"],
    }.items():
        agg = aggregate_by_condition(cells, models)
        for condition in CONDITIONS:
            cell = agg[condition]
            lines.append(f"| {stack} | {condition} | {cell['vuln']} | {cell['total']} | {pct(cell['vuln'], cell['total']):.1f}% |")

    lines += [
        "",
        "## Interpretation",
        "",
        "- GPT add-on data are complete: 1,080 valid add-on rows plus 360 reused control rows.",
        "- Claude add-on data are partial: 815 valid add-on rows currently collected out of 1,080 planned.",
        "- Pure-positive is not uniformly safer. The clearest early example is GPT-5.4 Mini on `md5-hash`, where pure-positive produced 14/20 vulnerable outputs while pure-negative and combined were 0/20.",
        "- Combined rules often repair pure-positive omissions, supporting the information-content explanation rather than a simple positive-vs-negative polarity rule.",
        "- Claude Opus is strongest overall but became vulnerable on `eval-dynamic` pure-positive, so even the strongest model is not uniformly protected by positive-only guidance.",
        "- Claude completion is currently blocked by OpenRouter 402 credit/max-token limits and Claude CLI 401 authentication.",
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
