#!/usr/bin/env python3
"""
Generate publication-quality charts for the PatchPilot / CodeCoach paper.
Outputs 300 DPI PNGs into ./figures/
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch

# ---------------------------------------------------------------------------
# Global style
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": False,
    "figure.facecolor": "white",
    "savefig.facecolor": "white",
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.15,
})

# Professional palette
CONTROL_COLOR = "#D9534F"   # warm coral-red
TREATMENT_COLOR = "#2E8B7A" # teal-green
POS_GREEN = "#2E8B7A"
NEG_RED = "#D9534F"
BLUE_ACCENT = "#3B7DD8"
ORANGE_ACCENT = "#E8913A"

FIGURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)


def _save(fig, name):
    path = os.path.join(FIGURES_DIR, name)
    fig.savefig(path)
    plt.close(fig)
    print(f"  saved {path}")


# ===================================================================
# Chart 1 -- Experiment 2: Mechanism Validation
# ===================================================================
def chart_mechanism_validation():
    models = ["Claude\nSonnet 4", "Nemotron\n120B", "GPT-OSS\n120B", "GPT-OSS\n20B"]
    control =   [27, 73, 93, 80]
    treatment = [ 0,  0,  3,  0]
    stars =     ["**", "***", "***", "***"]

    x = np.arange(len(models))
    w = 0.32

    fig, ax = plt.subplots(figsize=(7, 4.5))
    bars_c = ax.bar(x - w/2, control,   w, label="Control",   color=CONTROL_COLOR, edgecolor="white", linewidth=0.5)
    bars_t = ax.bar(x + w/2, treatment, w, label="Treatment", color=TREATMENT_COLOR, edgecolor="white", linewidth=0.5)

    ax.set_ylabel("Vulnerability Rate (%)")
    ax.set_title("Experiment 2: Mechanism Validation", fontweight="bold", pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=10)
    ax.set_ylim(0, 115)
    ax.legend(frameon=False, loc="upper left")

    # significance stars
    for i, star in enumerate(stars):
        y_top = max(control[i], treatment[i]) + 5
        ax.annotate(star, xy=(x[i], y_top), ha="center", va="bottom",
                    fontsize=13, fontweight="bold", color="#333333")

    # value labels on bars
    for bar in bars_c:
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{int(h)}%",
                    ha="center", va="bottom", fontsize=8.5, color="#555555")
    for bar in bars_t:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{int(h)}%",
                ha="center", va="bottom", fontsize=8.5, color="#555555")

    _save(fig, "fig-mechanism-validation.png")


# ===================================================================
# Chart 2 -- Experiment 3: End-to-End Pipeline
# ===================================================================
def chart_e2e_results():
    groups = ["Nemotron\n120B", "GPT-OSS\n120B", "Overall"]
    control =   [70, 67, 68.5]
    treatment = [56, 26, 40.7]

    x = np.arange(len(groups))
    w = 0.32

    fig, ax = plt.subplots(figsize=(6, 4.5))
    bars_c = ax.bar(x - w/2, control,   w, label="Control",   color=CONTROL_COLOR, edgecolor="white", linewidth=0.5)
    bars_t = ax.bar(x + w/2, treatment, w, label="Treatment", color=TREATMENT_COLOR, edgecolor="white", linewidth=0.5)

    ax.set_ylabel("Vulnerability Rate (%)")
    ax.set_title("Experiment 3: End-to-End Pipeline", fontweight="bold", pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(groups, fontsize=10)
    ax.set_ylim(0, 100)
    ax.legend(frameon=False, loc="upper left")

    # value labels
    for bars in [bars_c, bars_t]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 1.5,
                    f"{h:.1f}%" if h != int(h) else f"{int(h)}%",
                    ha="center", va="bottom", fontsize=8.5, color="#555555")

    # p-value annotation for Overall
    idx = 2
    y_top = max(control[idx], treatment[idx]) + 12
    ax.annotate("p = 0.004", xy=(x[idx], y_top), ha="center", va="bottom",
                fontsize=10, fontweight="bold", color=BLUE_ACCENT,
                bbox=dict(boxstyle="round,pad=0.25", fc="#EAF0FB", ec=BLUE_ACCENT, lw=0.8))

    _save(fig, "fig-e2e-results.png")


# ===================================================================
# Chart 3 -- Matched vs. Unmatched CWEs  (KEY CHART)
# ===================================================================
def chart_matched_vs_unmatched():
    groups = ["Matched CWEs\n(rules generated)", "Unmatched CWEs\n(no rules)"]
    control =   [83, 50]
    treatment = [30, 54]

    x = np.arange(len(groups))
    w = 0.30

    fig, ax = plt.subplots(figsize=(6.5, 5))
    bars_c = ax.bar(x - w/2, control,   w, label="Control",   color=CONTROL_COLOR, edgecolor="white", linewidth=0.5)
    bars_t = ax.bar(x + w/2, treatment, w, label="Treatment", color=TREATMENT_COLOR, edgecolor="white", linewidth=0.5)

    ax.set_ylabel("Vulnerability Rate (%)")
    ax.set_title("Treatment Effect: Matched vs. Unmatched CWEs", fontweight="bold", pad=18)
    ax.set_xticks(x)
    ax.set_xticklabels(groups, fontsize=10)
    ax.set_ylim(0, 115)
    ax.legend(frameon=False, loc="upper right")

    # value labels
    for bars in [bars_c, bars_t]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{int(h)}%",
                    ha="center", va="bottom", fontsize=9, color="#555555")

    # Annotation arrow + text for Matched (64% reduction)
    x_ctrl_matched = x[0] - w/2 + w/2   # center of control bar
    x_treat_matched = x[0] + w/2 + w/2  # right side area
    mid_x = x[0] + w + 0.12

    ax.annotate(
        "",
        xy=(mid_x, treatment[0]),
        xytext=(mid_x, control[0]),
        arrowprops=dict(arrowstyle="->", color=TREATMENT_COLOR, lw=2),
    )
    ax.text(mid_x + 0.08, (control[0] + treatment[0]) / 2, "64%\nreduction",
            ha="left", va="center", fontsize=9, fontweight="bold", color=TREATMENT_COLOR)

    # Annotation for Unmatched (no effect)
    mid_x2 = x[1] + w + 0.12
    ax.annotate(
        "",
        xy=(mid_x2, treatment[1]),
        xytext=(mid_x2, control[1]),
        arrowprops=dict(arrowstyle="->", color="#999999", lw=1.5, linestyle="dashed"),
    )
    ax.text(mid_x2 + 0.08, (control[1] + treatment[1]) / 2, "no\neffect",
            ha="left", va="center", fontsize=9, fontweight="bold", color="#888888")

    _save(fig, "fig-matched-vs-unmatched.png")


# ===================================================================
# Chart 4 -- Per-CWE Prevention Rate (End-to-End)
# ===================================================================
def chart_per_cwe_e2e():
    # CWE label, prevention rate (%), had rules generated?
    data = [
        ("CWE-319  (HTTP)",       100, True),
        ("CWE-338  (Random)",      67, True),
        ("CWE-94    (Eval)",       50, True),
        ("CWE-78    (Cmd Inj)",     0, True),
        ("CWE-328  (MD5)",        -25, False),
        ("CWE-22    (Path Trav)", -200, False),
    ]

    labels = [d[0] for d in data]
    rates  = [d[1] for d in data]
    has_rules = [d[2] for d in data]

    colors = [POS_GREEN if r > 0 else NEG_RED for r in rates]

    y = np.arange(len(labels))

    fig, ax = plt.subplots(figsize=(8.5, 4))
    bars = ax.barh(y, rates, color=colors, edgecolor="white", linewidth=0.5, height=0.55)

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.set_xlabel("Prevention Rate (%)")
    ax.set_title("Per-CWE Prevention Rate (End-to-End)", fontweight="bold", pad=14)
    ax.axvline(0, color="#999999", linewidth=0.8)
    ax.set_xlim(-230, 135)

    # Rule-match markers -- always place to the right of the bar end
    for i, has in enumerate(has_rules):
        tag = "rules" if has else "no rules"
        tag_color = TREATMENT_COLOR if has else "#999999"
        # For positive bars, place right of bar; for negative/zero, place right of zero line
        if rates[i] > 0:
            marker_x = rates[i] + 6
        elif rates[i] == 0:
            marker_x = 6
        else:
            marker_x = 6  # always right of zero for readability
        ax.text(marker_x, i, tag, ha="left", va="center", fontsize=8,
                fontstyle="italic", color=tag_color)

    # value labels inside bars (only for bars wide enough)
    for i, bar in enumerate(bars):
        val = rates[i]
        if abs(val) > 15:
            text_x = val / 2
            ax.text(text_x, i, f"{val}%", ha="center", va="center",
                    fontsize=9, fontweight="bold", color="white")
        elif val == 0:
            ax.text(-12, i, "0%", ha="center", va="center",
                    fontsize=9, fontweight="bold", color="#555555")

    ax.invert_yaxis()  # best result on top

    _save(fig, "fig-per-cwe-e2e.png")


# ===================================================================
# Main
# ===================================================================
if __name__ == "__main__":
    print("Generating charts ...")
    chart_mechanism_validation()
    chart_e2e_results()
    chart_matched_vs_unmatched()
    chart_per_cwe_e2e()
    print("Done.")
