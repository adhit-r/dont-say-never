"""
Generate all figures for:
"Rules Work, Polarity Doesn't: A Multi-Model Replication of Security Rule
 Framing Effects in LLM Coding Agents"

Reads 6-model replication data from experiments/data/replication/.

Outputs:
  figures/fig-rule-injection-bars.png      — Main result: vuln rate by model × condition
  figures/fig-polarity-heatmap.png         — Polarity delta heatmap (neg vs pos per model×prompt)
  figures/fig-per-prompt-grid.png          — 6-panel grid: per-prompt vuln rate by condition
  figures/fig-control-baseline-heatmap.png — Control baseline rates (model × prompt)
"""

import json
import math
import os

import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np
from scipy import stats

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(OUT_DIR, "..", "experiments", "data", "replication")

# ─── Config ────────────────────────────────────────────────────────────────

MODELS = [
    ("claude-opus-4.6",   "Claude\nOpus 4.6"),
    ("claude-sonnet-4.6", "Claude\nSonnet 4.6"),
    ("claude-haiku-4.5",  "Claude\nHaiku 4.5"),
    ("claude-opus-4.1",   "Claude\nOpus 4.1"),
    ("gemma-4-31b-it",    "Gemma 4\n31B"),
    ("gpt-5.4-mini",      "GPT-5.4\nMini"),
]

PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]
PROMPT_LABELS = ["eval-usage", "md5-hash", "http-url", "insecure-\nrandom", "eval-\ndynamic", "weak-hash"]
CONDITIONS = ["control", "negative-framing", "positive-framing"]
COND_SHORT = ["Control", "Negative\n(prohibition)", "Positive\n(alternative)"]
COND_COLORS = ["#95a5a6", "#e74c3c", "#2ecc71"]

# ─── Load data ─────────────────────────────────────────────────────────────

def load_model(filename):
    """Load a replication JSON and return {prompt_id: {condition: {vuln, total, errors}}}."""
    with open(os.path.join(DATA_DIR, filename)) as f:
        raw = json.load(f)
    summary = raw.get("summary", {})
    out = {}
    for key, conds in summary.items():
        prompt_id = key.split("/")[-1] if "/" in key else key
        out[prompt_id] = {}
        for cond in CONDITIONS:
            c = conds.get(cond, {})
            total = c.get("total", 0)
            vuln = c.get("vuln", 0)
            errors = c.get("errors", 0)
            out[prompt_id][cond] = {"vuln": vuln, "valid": total - errors, "total": total}
    return out

model_data = {}
for mid, label in MODELS:
    model_data[mid] = load_model(f"{mid}.json")


def get_rate(mdata, prompt, cond):
    d = mdata.get(prompt, {}).get(cond, {})
    valid = d.get("valid", 0)
    return d["vuln"] / valid if valid > 0 else float("nan")


def get_counts(mdata, prompt, cond):
    d = mdata.get(prompt, {}).get(cond, {})
    return d.get("vuln", 0), d.get("valid", 0)


def cohens_h(p1, p2):
    return 2 * (math.asin(math.sqrt(max(0, min(1, p1)))) -
                math.asin(math.sqrt(max(0, min(1, p2)))))

# ─── Figure 1: Rule-Injection Aggregate Bars ──────────────────────────────

def make_rule_injection_bars():
    """Grouped bar chart: aggregate vuln rates by model × condition."""
    fig, ax = plt.subplots(figsize=(12, 6))

    rates = {cond: [] for cond in CONDITIONS}
    for mid, _ in MODELS:
        mdata = model_data[mid]
        for cond in CONDITIONS:
            tv, tn = 0, 0
            for prompt in PROMPTS:
                v, n = get_counts(mdata, prompt, cond)
                tv += v
                tn += n
            rates[cond].append(tv / tn * 100 if tn > 0 else 0)

    x = np.arange(len(MODELS))
    width = 0.25

    for i, (cond, label, color) in enumerate(zip(CONDITIONS, COND_SHORT, COND_COLORS)):
        bars = ax.bar(x + i * width, rates[cond], width, label=label,
                      color=color, edgecolor="white", linewidth=0.5)
        for bar, val in zip(bars, rates[cond]):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.2,
                    f"{val:.0f}%", ha="center", va="bottom", fontsize=8, fontweight="bold")

    ax.set_ylabel("Vulnerability Rate (%)", fontsize=12)
    ax.set_title("Rule Injection Reliably Reduces Vulnerability Across 6 Models",
                 fontsize=14, fontweight="bold")
    ax.set_xticks(x + width)
    ax.set_xticklabels([l for _, l in MODELS], fontsize=9)
    ax.set_ylim(0, 100)
    ax.legend(fontsize=10, loc="upper right", framealpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.axhline(y=0, color="black", linewidth=0.5)

    # Add significance stars
    for i, (mid, _) in enumerate(MODELS):
        mdata = model_data[mid]
        ctrl_v, ctrl_n = 0, 0
        neg_v, neg_n = 0, 0
        for prompt in PROMPTS:
            v, n = get_counts(mdata, prompt, "control")
            ctrl_v += v; ctrl_n += n
            v, n = get_counts(mdata, prompt, "negative-framing")
            neg_v += v; neg_n += n
        if ctrl_n > 0 and neg_n > 0:
            table = [[neg_v, neg_n - neg_v], [ctrl_v, ctrl_n - ctrl_v]]
            _, p = stats.fisher_exact(table)
            if p < 0.001:
                star_y = max(rates["control"][i], rates["negative-framing"][i], rates["positive-framing"][i]) + 6
                ax.text(x[i] + width, star_y, "***", ha="center", fontsize=9, color="#333")

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-rule-injection-bars.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Figure 2: Polarity Heatmap ───────────────────────────────────────────

def make_polarity_heatmap():
    """Heatmap: (positive - negative) delta per model × prompt.
    Shows whether positive framing helps (blue) or hurts (red) vs negative."""
    fig, ax = plt.subplots(figsize=(10, 5.5))

    model_labels = [l for _, l in MODELS]
    matrix = np.full((len(MODELS), len(PROMPTS)), np.nan)
    annotations = [[None]*len(PROMPTS) for _ in range(len(MODELS))]

    for i, (mid, _) in enumerate(MODELS):
        mdata = model_data[mid]
        for j, prompt in enumerate(PROMPTS):
            neg_rate = get_rate(mdata, prompt, "negative-framing")
            pos_rate = get_rate(mdata, prompt, "positive-framing")
            if not (np.isnan(neg_rate) or np.isnan(pos_rate)):
                delta = pos_rate - neg_rate
                matrix[i, j] = delta
                # Fisher test for significance
                neg_v, neg_n = get_counts(mdata, prompt, "negative-framing")
                pos_v, pos_n = get_counts(mdata, prompt, "positive-framing")
                if neg_n > 0 and pos_n > 0:
                    table = [[pos_v, pos_n - pos_v], [neg_v, neg_n - neg_v]]
                    _, p = stats.fisher_exact(table)
                    sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else ""
                else:
                    sig = ""
                sign = "+" if delta > 0 else ""
                annotations[i][j] = f"{sign}{delta*100:.0f}%{sig}"

    cmap = plt.cm.RdBu_r  # red = positive worse, blue = positive better
    norm = mcolors.TwoSlopeNorm(vmin=-0.8, vcenter=0, vmax=0.8)
    im = ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")

    for i in range(len(MODELS)):
        for j in range(len(PROMPTS)):
            val = matrix[i, j]
            if np.isnan(val):
                ax.text(j, i, "—", ha="center", va="center", color="gray", fontsize=10)
            else:
                color = "white" if abs(val) > 0.35 else "black"
                ax.text(j, i, annotations[i][j], ha="center", va="center",
                        color=color, fontsize=9, fontweight="bold" if abs(val) > 0.2 else "normal")

    ax.set_xticks(range(len(PROMPTS)))
    ax.set_xticklabels(PROMPT_LABELS, fontsize=9, ha="center")
    ax.set_yticks(range(len(MODELS)))
    ax.set_yticklabels([l.replace('\n', ' ') for _, l in MODELS], fontsize=10)
    ax.set_title("Polarity Delta: Positive − Negative Framing\n(Red = positive worse, Blue = positive better)",
                 fontsize=13, fontweight="bold", pad=15)

    for edge in range(len(PROMPTS) + 1):
        ax.axvline(edge - 0.5, color="white", linewidth=2)
    for edge in range(len(MODELS) + 1):
        ax.axhline(edge - 0.5, color="white", linewidth=2)

    cbar = fig.colorbar(im, ax=ax, shrink=0.8, pad=0.03)
    cbar.set_label("Δ Vulnerability Rate (Positive − Negative)", fontsize=10)
    cbar.set_ticks([-0.8, -0.4, 0, 0.4, 0.8])
    cbar.set_ticklabels(["−80%\n(pos better)", "−40%", "0%", "+40%", "+80%\n(pos worse)"])

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-polarity-heatmap.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Figure 3: Per-Prompt Grid ────────────────────────────────────────────

def make_per_prompt_grid():
    """6-panel grid (2×3): one subplot per prompt, bars by model × condition."""
    fig, axes = plt.subplots(2, 3, figsize=(16, 9), sharey=True)
    axes_flat = axes.flatten()

    model_short = [l.replace('\n', ' ') for _, l in MODELS]

    for idx, (prompt, prompt_label) in enumerate(zip(PROMPTS, PROMPT_LABELS)):
        ax = axes_flat[idx]
        x = np.arange(len(MODELS))
        width = 0.25

        for ci, (cond, color) in enumerate(zip(CONDITIONS, COND_COLORS)):
            vals = []
            for mid, _ in MODELS:
                mdata = model_data[mid]
                v, n = get_counts(mdata, prompt, cond)
                vals.append(v / n * 100 if n > 0 else 0)
            ax.bar(x + ci * width, vals, width, color=color, edgecolor="white", linewidth=0.5)

        ax.set_title(prompt_label.replace('\n', ''), fontsize=11, fontweight="bold")
        ax.set_xticks(x + width)
        ax.set_xticklabels([l.split('\n')[0][:8] for _, l in MODELS], fontsize=7, rotation=30, ha="right")
        ax.set_ylim(0, 110)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        if idx % 3 == 0:
            ax.set_ylabel("Vuln Rate (%)", fontsize=10)

    # Legend on last subplot
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=c, label=l.replace('\n', ' '))
                       for c, l in zip(COND_COLORS, COND_SHORT)]
    axes_flat[-1].legend(handles=legend_elements, fontsize=8, loc="upper right")

    fig.suptitle("Per-Prompt Vulnerability Rates Across 6 Models",
                 fontsize=14, fontweight="bold", y=1.01)
    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-per-prompt-grid.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Figure 4: Control Baseline Heatmap ───────────────────────────────────

def make_control_baseline_heatmap():
    """Heatmap of control (no-rule) baseline vuln rates — shows prompt/model difficulty."""
    fig, ax = plt.subplots(figsize=(10, 5))

    matrix = np.full((len(MODELS), len(PROMPTS)), np.nan)

    for i, (mid, _) in enumerate(MODELS):
        mdata = model_data[mid]
        for j, prompt in enumerate(PROMPTS):
            rate = get_rate(mdata, prompt, "control")
            matrix[i, j] = rate

    cmap = plt.cm.YlOrRd
    im = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=1, aspect="auto")

    for i in range(len(MODELS)):
        for j in range(len(PROMPTS)):
            val = matrix[i, j]
            if np.isnan(val):
                ax.text(j, i, "—", ha="center", va="center", color="gray", fontsize=10)
            else:
                v, n = get_counts(model_data[MODELS[i][0]], PROMPTS[j], "control")
                color = "white" if val > 0.6 else "black"
                ax.text(j, i, f"{val*100:.0f}%\n({v}/{n})", ha="center", va="center",
                        color=color, fontsize=9)

    ax.set_xticks(range(len(PROMPTS)))
    ax.set_xticklabels(PROMPT_LABELS, fontsize=9, ha="center")
    ax.set_yticks(range(len(MODELS)))
    ax.set_yticklabels([l.replace('\n', ' ') for _, l in MODELS], fontsize=10)
    ax.set_title("Baseline Vulnerability Rates (Control, No Rules)\nHigher = prompt elicits more vulnerable code by default",
                 fontsize=13, fontweight="bold", pad=15)

    for edge in range(len(PROMPTS) + 1):
        ax.axvline(edge - 0.5, color="white", linewidth=2)
    for edge in range(len(MODELS) + 1):
        ax.axhline(edge - 0.5, color="white", linewidth=2)

    cbar = fig.colorbar(im, ax=ax, shrink=0.8, pad=0.03)
    cbar.set_label("Vulnerability Rate (%)", fontsize=10)
    cbar.set_ticks([0, 0.25, 0.5, 0.75, 1.0])
    cbar.set_ticklabels(["0%", "25%", "50%", "75%", "100%"])

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-control-baseline-heatmap.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Run everything ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generating replication figures from 6-model data...")
    print(f"Data dir: {DATA_DIR}")
    print(f"Output dir: {OUT_DIR}")
    print()
    make_rule_injection_bars()
    make_polarity_heatmap()
    make_per_prompt_grid()
    make_control_baseline_heatmap()
    print("\nAll 4 figures generated.")
