#!/usr/bin/env python3
"""Generate submission-focused visual summaries.

These figures are designed for the paper, not exploratory debugging. They read
the finalized replication, non-API, and four-arm add-on datasets.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "experiments" / "data" / "pro-replication"
OUT = ROOT / "figures"

MODELS = [
    ("gpt-5.4", "GPT-5.4", "GPT"),
    ("gpt-5.4-mini", "GPT-5.4 Mini", "GPT"),
    ("gpt-5.3-codex", "GPT-5.3 Codex", "GPT"),
    ("claude-opus-4.6", "Opus 4.6", "Claude"),
    ("claude-sonnet-4.6", "Sonnet 4.6", "Claude"),
    ("claude-haiku-4.5", "Haiku 4.5", "Claude"),
]
PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]
FOUR_ARM = ["control", "pure-negative", "pure-positive", "combined"]

COLORS = {
    "control": "#747C8A",
    "pure-negative": "#B84A3A",
    "pure-positive": "#2F8F83",
    "combined": "#2F5F8F",
    "safe": "#2F6B4F",
    "warn": "#C28A2C",
    "ink": "#23272F",
}


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text()).get("results", [])


def pct(v: int, n: int) -> float:
    return 100.0 * v / n if n else 0.0


def save(fig: plt.Figure, name: str) -> None:
    path = OUT / name
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"saved {path}")


def count(rows: list[dict], condition: str | None = None, prompt: str | None = None) -> tuple[int, int]:
    valid = [
        r for r in rows
        if not r.get("error")
        and (condition is None or r.get("condition") == condition)
        and (prompt is None or r.get("prompt_id") == prompt)
    ]
    return sum(1 for r in valid if r.get("vulnerable")), len(valid)


def four_arm_rows(model_id: str) -> dict[str, list[dict]]:
    main = load(DATA / "main" / f"{model_id}.json")
    addons = load(DATA / "four-arm-addons" / f"{model_id}.json")
    return {
        "control": [r for r in main if r.get("condition") == "control"],
        "pure-negative": [r for r in addons if r.get("condition") == "pure-negative"],
        "pure-positive": [r for r in addons if r.get("condition") == "pure-positive"],
        "combined": [r for r in addons if r.get("condition") == "combined"],
    }


def plot_four_arm_model_heatmap() -> None:
    matrix = np.zeros((len(MODELS), len(FOUR_ARM)))
    labels = [["" for _ in FOUR_ARM] for _ in MODELS]
    for i, (model_id, _, _) in enumerate(MODELS):
        grouped = four_arm_rows(model_id)
        for j, condition in enumerate(FOUR_ARM):
            v, n = count(grouped[condition])
            matrix[i, j] = pct(v, n)
            labels[i][j] = f"{v}/{n}\n{matrix[i, j]:.1f}%"

    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    im = ax.imshow(matrix, cmap="YlOrRd", vmin=0, vmax=70, aspect="auto")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            ax.text(
                j,
                i,
                labels[i][j],
                ha="center",
                va="center",
                fontsize=8,
                color="white" if matrix[i, j] > 38 else "black",
            )
    ax.set_xticks(range(len(FOUR_ARM)))
    ax.set_xticklabels(["Control", "Pure\nnegative", "Pure\npositive", "Combined"])
    ax.set_yticks(range(len(MODELS)))
    ax.set_yticklabels([label for _, label, _ in MODELS])
    ax.set_title("Four-arm decomposition by model", fontsize=14, fontweight="bold")
    ax.set_xlabel("Rule condition")
    cbar = fig.colorbar(im, ax=ax, shrink=0.78)
    cbar.set_label("Vulnerable outputs (%)")
    fig.tight_layout()
    save(fig, "fig-four-arm-model-heatmap.png")


def plot_rule_design_takeaway() -> None:
    totals = {}
    for condition in FOUR_ARM:
        vuln = total = 0
        for model_id, _, _ in MODELS:
            grouped = four_arm_rows(model_id)
            v, n = count(grouped[condition])
            vuln += v
            total += n
        totals[condition] = (vuln, total, pct(vuln, total))

    labels = ["No rule", "Forbidden\nonly", "Safe path\nonly", "Both boundary\nand safe path"]
    conditions = ["control", "pure-negative", "pure-positive", "combined"]
    values = [totals[c][2] for c in conditions]
    counts = [f"{totals[c][0]}/{totals[c][1]}" for c in conditions]

    fig, ax = plt.subplots(figsize=(9.4, 4.9))
    bars = ax.bar(
        range(len(values)),
        values,
        color=[COLORS["control"], COLORS["pure-negative"], COLORS["pure-positive"], COLORS["combined"]],
        width=0.62,
    )
    for bar, value, label in zip(bars, values, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 2.2, f"{value:.1f}%\n{label}",
                ha="center", va="bottom", fontsize=10)
    ax.annotate(
        "Best observed rule form",
        xy=(3, values[3]),
        xytext=(2.25, 46),
        arrowprops={"arrowstyle": "->", "lw": 1.5, "color": COLORS["ink"]},
        fontsize=11,
        color=COLORS["ink"],
    )
    ax.set_title("Security rule design: information content beats polarity", fontsize=14, fontweight="bold")
    ax.set_ylabel("Vulnerable outputs (%)")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 72)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", alpha=0.18)
    fig.tight_layout()
    save(fig, "fig-rule-design-takeaway.png")


def plot_evidence_stack() -> None:
    main_v = main_n = 0
    rule_v = rule_n = 0
    for model_id, _, _ in MODELS:
        rows = load(DATA / "main" / f"{model_id}.json")
        v, n = count(rows, "control")
        main_v += v
        main_n += n
        for condition in ("negative-framing", "positive-framing"):
            v, n = count(rows, condition)
            rule_v += v
            rule_n += n

    nonapi_rows = []
    for model_id, _, _ in MODELS:
        nonapi_rows.extend(load(DATA / "non-api" / f"{model_id}.json"))
    formula_v, formula_n = count(nonapi_rows, prompt="eval-no-mention")
    inert_v = inert_n = 0
    for prompt in ("hash-no-mention", "token-no-mention"):
        v, n = count(nonapi_rows, prompt=prompt)
        inert_v += v
        inert_n += n

    combined_v = combined_n = 0
    for model_id, _, _ in MODELS:
        v, n = count(four_arm_rows(model_id)["combined"])
        combined_v += v
        combined_n += n

    cards = [
        ("Main replication", "Rules reduce vulnerability", f"{pct(main_v, main_n):.1f}% control", f"{pct(rule_v, rule_n):.1f}% with rules", "2,160 trials"),
        ("Non-API extension", "Prompt semantics matter", f"{pct(formula_v, formula_n):.1f}% formula risk", f"{inert_v}/{inert_n} hash/token risk", "1,080 trials"),
        ("Four-arm decomposition", "Information content wins", f"{pct(combined_v, combined_n):.1f}% combined", "pure-positive not safest", "2,160 add-on rows"),
    ]

    fig, ax = plt.subplots(figsize=(11, 4.2))
    ax.axis("off")
    x_positions = [0.02, 0.35, 0.68]
    for idx, (title, headline, left, right, footer) in enumerate(cards):
        x = x_positions[idx]
        rect = plt.Rectangle((x, 0.12), 0.30, 0.76, transform=ax.transAxes,
                             facecolor="#F6F7F4", edgecolor="#C7CDC2", linewidth=1.2)
        ax.add_patch(rect)
        ax.text(x + 0.02, 0.78, title.upper(), transform=ax.transAxes,
                fontsize=9, color="#5A5F66", fontweight="bold")
        ax.text(x + 0.02, 0.62, headline, transform=ax.transAxes,
                fontsize=14, color=COLORS["ink"], fontweight="bold")
        ax.text(x + 0.02, 0.43, left, transform=ax.transAxes,
                fontsize=18, color=COLORS["warn"], fontweight="bold")
        ax.text(x + 0.02, 0.30, right, transform=ax.transAxes,
                fontsize=12, color=COLORS["safe"], fontweight="bold")
        ax.text(x + 0.02, 0.18, footer, transform=ax.transAxes,
                fontsize=9, color="#5A5F66")
    ax.set_title("Evidence stack for security-rule framing", fontsize=15, fontweight="bold", y=0.98)
    save(fig, "fig-evidence-stack-infographic.png")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    plot_four_arm_model_heatmap()
    plot_rule_design_takeaway()
    plot_evidence_stack()


if __name__ == "__main__":
    main()
