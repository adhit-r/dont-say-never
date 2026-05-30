#!/usr/bin/env python3
"""
Generate figures for experiments/data/pro-replication.

This script is safe to run on partial data. Missing model/suite files are skipped.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "experiments" / "data" / "pro-replication"
OUT_DIR = ROOT / "figures"

MODELS = [
    ("gpt-5.4", "GPT-5.4", "GPT"),
    ("gpt-5.4-mini", "GPT-5.4\nMini", "GPT"),
    ("gpt-5.3-codex", "GPT-5.3\nCodex", "GPT"),
    ("claude-opus-4.6", "Claude\nOpus 4.6", "Claude"),
    ("claude-sonnet-4.6", "Claude\nSonnet 4.6", "Claude"),
    ("claude-haiku-4.5", "Claude\nHaiku 4.5", "Claude"),
]

MAIN_CONDITIONS = ["control", "negative-framing", "positive-framing"]
FOUR_ARM_CONDITIONS = ["control", "pure-negative", "pure-positive", "combined"]

COLORS = {
    "control": "#8d99ae",
    "negative-framing": "#d1495b",
    "positive-framing": "#2a9d8f",
    "pure-negative": "#d1495b",
    "pure-positive": "#2a9d8f",
    "combined": "#3d5a80",
}


def load_suite_model(suite: str, model_id: str) -> dict | None:
    path = DATA_DIR / suite / f"{model_id}.json"
    if not path.exists():
        return None
    with path.open() as f:
        return json.load(f)


def aggregate_rate(raw: dict, condition: str) -> tuple[int, int]:
    vuln = 0
    valid = 0
    for r in raw.get("results", []):
        if r.get("condition") != condition or r.get("error"):
            continue
        valid += 1
        vuln += 1 if r.get("vulnerable") else 0
    return vuln, valid


def cell_rate(raw: dict, prompt_id: str, condition: str) -> tuple[int, int]:
    vuln = 0
    valid = 0
    for r in raw.get("results", []):
        if r.get("prompt_id") != prompt_id or r.get("condition") != condition or r.get("error"):
            continue
        valid += 1
        vuln += 1 if r.get("vulnerable") else 0
    return vuln, valid


def pct(v: int, n: int) -> float:
    return 100.0 * v / n if n else math.nan


def save(fig, name: str) -> None:
    path = OUT_DIR / name
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {path}")


def plot_bars_with_missing(ax, xs, rates, width, color, label):
    bars = []
    for x, rate in zip(xs, rates):
        if math.isnan(rate):
            bar = ax.bar(x, 0, width, color="white", edgecolor=color, hatch="//", label=label if not bars else None)
            ax.text(x, 3, "missing", ha="center", va="bottom", fontsize=7, rotation=90, color=color)
        else:
            bar = ax.bar(x, rate, width, color=color, label=label if not bars else None)
        bars.extend(bar)
    return bars


def make_main_bars() -> None:
    rows = [(m, label, group, load_suite_model("main", m)) for m, label, group in MODELS]
    rows = [r for r in rows if r[3]]
    if not rows:
        print("No main-suite pro data yet")
        return

    fig, ax = plt.subplots(figsize=(11, 5.8))
    x = np.arange(len(rows))
    width = 0.24
    for i, cond in enumerate(MAIN_CONDITIONS):
        rates = []
        labels = []
        for _, _, _, raw in rows:
            v, n = aggregate_rate(raw, cond)
            rates.append(pct(v, n))
            labels.append(f"{v}/{n}" if n else "")
        bars = plot_bars_with_missing(
            ax,
            x + (i - 1) * width,
            rates,
            width,
            COLORS[cond],
            cond.replace("-", " "),
        )
        for bar, rate, label in zip(bars, rates, labels):
            if label and not math.isnan(rate):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"{rate:.0f}%\n{label}",
                        ha="center", va="bottom", fontsize=7)

    ax.set_title("Pro Replication: GPT vs Claude Rule-Framing Effects", fontsize=13, fontweight="bold")
    ax.set_ylabel("Vulnerability rate (%)")
    ax.set_xticks(x)
    ax.set_xticklabels([label for _, label, _, _ in rows])
    ax.set_ylim(0, 100)
    ax.legend(frameon=False, ncols=3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for idx, (_, _, group, _) in enumerate(rows):
        ax.text(idx, -12, group, ha="center", va="top", fontsize=8, transform=ax.get_xaxis_transform())

    fig.tight_layout()
    save(fig, "fig-pro-gpt-vs-claude-bars.png")


def make_polarity_heatmap() -> None:
    rows = [(m, label, load_suite_model("main", m)) for m, label, _ in MODELS]
    rows = [r for r in rows if r[2]]
    if not rows:
        print("No main-suite pro data yet")
        return

    prompts = sorted({r.get("prompt_id") for _, _, raw in rows for r in raw.get("results", []) if r.get("prompt_id")})
    matrix = np.full((len(rows), len(prompts)), np.nan)

    for i, (_, _, raw) in enumerate(rows):
        for j, prompt in enumerate(prompts):
            neg_v, neg_n = cell_rate(raw, prompt, "negative-framing")
            pos_v, pos_n = cell_rate(raw, prompt, "positive-framing")
            if neg_n and pos_n:
                matrix[i, j] = pct(pos_v, pos_n) - pct(neg_v, neg_n)

    fig, ax = plt.subplots(figsize=(10, 4.8))
    im = ax.imshow(matrix, cmap="RdBu_r", vmin=-80, vmax=80, aspect="auto")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            val = matrix[i, j]
            text = "--" if math.isnan(val) else f"{val:+.0f}%"
            ax.text(j, i, text, ha="center", va="center", fontsize=8,
                    color="white" if not math.isnan(val) and abs(val) > 35 else "black")
    ax.set_title("Pro Replication Polarity Delta: Positive - Negative", fontsize=13, fontweight="bold")
    ax.set_xticks(range(len(prompts)))
    ax.set_xticklabels(prompts, rotation=30, ha="right")
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([label.replace("\n", " ") for _, label, _ in rows])
    cbar = fig.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("Delta vulnerability rate, percentage points")
    fig.tight_layout()
    save(fig, "fig-pro-polarity-heatmap.png")


def make_control_baseline_heatmap() -> None:
    rows = [(m, label, load_suite_model("main", m)) for m, label, _ in MODELS]
    rows = [r for r in rows if r[2]]
    if not rows:
        print("No main-suite pro data yet")
        return

    prompts = sorted({r.get("prompt_id") for _, _, raw in rows for r in raw.get("results", []) if r.get("prompt_id")})
    matrix = np.full((len(rows), len(prompts)), np.nan)

    for i, (_, _, raw) in enumerate(rows):
        for j, prompt in enumerate(prompts):
            v, n = cell_rate(raw, prompt, "control")
            if n:
                matrix[i, j] = pct(v, n)

    fig, ax = plt.subplots(figsize=(10, 4.8))
    im = ax.imshow(matrix, cmap="YlOrRd", vmin=0, vmax=100, aspect="auto")
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            val = matrix[i, j]
            text = "--" if math.isnan(val) else f"{val:.0f}%"
            ax.text(j, i, text, ha="center", va="center", fontsize=8,
                    color="white" if not math.isnan(val) and val > 55 else "black")
    ax.set_title("Control Baseline Vulnerability by Model and Prompt", fontsize=13, fontweight="bold")
    ax.set_xticks(range(len(prompts)))
    ax.set_xticklabels(prompts, rotation=30, ha="right")
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([label.replace("\n", " ") for _, label, _ in rows])
    cbar = fig.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("Control-condition vulnerability rate (%)")
    fig.tight_layout()
    save(fig, "fig-pro-control-baseline-heatmap.png")


def make_four_arm() -> None:
    rows = [(m, label, load_suite_model("four-arm", m)) for m, label, _ in MODELS]
    rows = [r for r in rows if r[2]]
    if not rows:
        print("No four-arm pro data yet")
        return

    fig, ax = plt.subplots(figsize=(12, 5.8))
    x = np.arange(len(rows))
    width = 0.18
    for i, cond in enumerate(FOUR_ARM_CONDITIONS):
        rates = []
        for _, _, raw in rows:
            v, n = aggregate_rate(raw, cond)
            rates.append(pct(v, n))
        bars = plot_bars_with_missing(
            ax,
            x + (i - 1.5) * width,
            rates,
            width,
            COLORS[cond],
            cond.replace("-", " "),
        )
        for bar, rate in zip(bars, rates):
            if not math.isnan(rate):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"{rate:.0f}%",
                        ha="center", va="bottom", fontsize=7)

    ax.set_title("Information-Content Decomposition: Pure Negative vs Pure Positive vs Combined",
                 fontsize=13, fontweight="bold")
    ax.set_ylabel("Vulnerability rate (%)")
    ax.set_xticks(x)
    ax.set_xticklabels([label for _, label, _ in rows])
    ax.set_ylim(0, 100)
    ax.legend(frameon=False, ncols=4)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    save(fig, "fig-pro-four-arm-decomposition.png")


def make_suite_bars(suite: str, filename: str, title: str) -> None:
    rows = [(m, label, load_suite_model(suite, m)) for m, label, _ in MODELS]
    rows = [r for r in rows if r[2]]
    if not rows:
        print(f"No {suite} pro data yet")
        return

    fig, ax = plt.subplots(figsize=(11, 5.4))
    x = np.arange(len(rows))
    width = 0.24
    for i, cond in enumerate(MAIN_CONDITIONS):
        rates = []
        for _, _, raw in rows:
            v, n = aggregate_rate(raw, cond)
            rates.append(pct(v, n))
        plot_bars_with_missing(
            ax,
            x + (i - 1) * width,
            rates,
            width,
            COLORS[cond],
            cond.replace("-", " "),
        )
    ax.set_title(title, fontsize=13, fontweight="bold")
    ax.set_ylabel("Vulnerability rate (%)")
    ax.set_xticks(x)
    ax.set_xticklabels([label for _, label, _ in rows])
    ax.set_ylim(0, 100)
    ax.legend(frameon=False, ncols=3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    save(fig, filename)


def main() -> None:
    make_main_bars()
    make_polarity_heatmap()
    make_control_baseline_heatmap()
    make_four_arm()
    make_suite_bars("non-api", "fig-pro-non-api-control.png", "Non-API-Naming Control")
    make_suite_bars("cross-language", "fig-pro-cross-language.png", "Cross-Language Replication")


if __name__ == "__main__":
    main()
