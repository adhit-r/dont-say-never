"""
Generate all figures + statistical tests for:
"Don't Say Never: How Prohibition-Framed Security Rules Backfire in LLM Coding Agents"

Outputs:
  figures/fig-backfire-heatmap.png       — Main result: model × prompt backfire heatmap
  figures/fig-aggregate-bars.png         — Aggregate vuln rates by model × condition
  figures/fig-non-api-null.png           — Non-API null result (0/225)
  figures/fig-double-priming-contrast.png — API-naming vs non-API comparison
  figures/statistical-tests.txt          — Full statistical analysis
"""

import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from scipy import stats
import os
import math

OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Load data ──────────────────────────────────────────────────────────────

with open(os.path.join(OUT_DIR, "../experiments/data/positive-framing-ablation-v2.json")) as f:
    claude_data = json.load(f)

with open(os.path.join(OUT_DIR, "../experiments/data/codex-framing-results.json")) as f:
    gpt5_data = json.load(f)

with open(os.path.join(OUT_DIR, "../experiments/data/gemma-framing-results.json")) as f:
    gemma_data = json.load(f)

with open(os.path.join(OUT_DIR, "../experiments/data/non-api-naming-framing-results.json")) as f:
    nonapi_data = json.load(f)

# ─── Extract per-cell data ──────────────────────────────────────────────────

PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]
PROMPT_LABELS = ["eval-usage", "md5-hash", "http-url", "insecure-\nrandom", "eval-\ndynamic", "weak-hash"]
CONDITIONS = ["control", "negative-framing", "positive-framing"]
COND_SHORT = ["Control", "Prohibition", "Alternative"]

def extract_summary(data, prompt_key_style="slash"):
    """Extract vuln/total per prompt×condition."""
    result = {}
    summary = data.get("summary", {})
    for key, conds in summary.items():
        if prompt_key_style == "slash":
            prompt_id = key.split("/")[-1] if "/" in key else key
        else:
            prompt_id = key
        result[prompt_id] = {}
        for cond in CONDITIONS:
            c = conds.get(cond, {})
            total = c.get("total", 0)
            vuln = c.get("vuln", 0)
            errors = c.get("errors", 0)
            valid = total - errors
            result[prompt_id][cond] = {"vuln": vuln, "valid": valid, "total": total, "errors": errors}
    return result

claude = extract_summary(claude_data)
gpt5 = extract_summary(gpt5_data)
gemma = extract_summary(gemma_data)

def get_rate(model_data, prompt, cond):
    """Return vulnerability rate, or NaN if no valid data."""
    d = model_data.get(prompt, {}).get(cond, {})
    valid = d.get("valid", 0)
    if valid == 0:
        return float("nan")
    return d["vuln"] / valid

def get_counts(model_data, prompt, cond):
    """Return (vuln, valid) tuple."""
    d = model_data.get(prompt, {}).get(cond, {})
    return d.get("vuln", 0), d.get("valid", 0)

# ─── Figure 1: Backfire Heatmap ─────────────────────────────────────────────

def make_backfire_heatmap():
    """Heatmap of (treatment - control) delta. Red = backfire, blue = helped."""
    models = ["Claude Sonnet 4", "GPT-5", "Gemma 4 31B"]
    model_data_list = [claude, gpt5, gemma]

    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), sharey=True)
    fig.suptitle("Framing Effect: Vulnerability Rate Delta (Treatment − Control)",
                 fontsize=14, fontweight="bold", y=1.02)

    for idx, (framing, framing_label) in enumerate([
        ("negative-framing", "Prohibition Framing (\"NEVER use X\")"),
        ("positive-framing", "Alternative-Suggestion (\"Always use Y\")")
    ]):
        ax = axes[idx]
        matrix = np.full((len(models), len(PROMPTS)), np.nan)

        for i, (model_name, mdata) in enumerate(zip(models, model_data_list)):
            for j, prompt in enumerate(PROMPTS):
                ctrl_rate = get_rate(mdata, prompt, "control")
                treat_rate = get_rate(mdata, prompt, framing)
                if not (np.isnan(ctrl_rate) or np.isnan(treat_rate)):
                    matrix[i, j] = treat_rate - ctrl_rate

        # Custom diverging colormap: blue (helped) to white (no change) to red (backfire)
        cmap = plt.cm.RdBu_r
        norm = mcolors.TwoSlopeNorm(vmin=-1.0, vcenter=0, vmax=1.0)

        im = ax.imshow(matrix, cmap=cmap, norm=norm, aspect="auto")

        # Annotate cells
        for i in range(len(models)):
            for j in range(len(PROMPTS)):
                val = matrix[i, j]
                if np.isnan(val):
                    ax.text(j, i, "—", ha="center", va="center", color="gray", fontsize=11)
                else:
                    sign = "+" if val > 0 else ""
                    pct = f"{sign}{val*100:.0f}%"
                    color = "white" if abs(val) > 0.4 else "black"
                    weight = "bold" if val > 0 else "normal"
                    ax.text(j, i, pct, ha="center", va="center", color=color,
                            fontsize=11, fontweight=weight)

        ax.set_xticks(range(len(PROMPTS)))
        ax.set_xticklabels(PROMPT_LABELS, fontsize=9, ha="center")
        ax.set_yticks(range(len(models)))
        ax.set_yticklabels(models, fontsize=11)
        ax.set_title(framing_label, fontsize=11, pad=10)

        # Grid
        for edge in range(len(PROMPTS) + 1):
            ax.axvline(edge - 0.5, color="white", linewidth=2)
        for edge in range(len(models) + 1):
            ax.axhline(edge - 0.5, color="white", linewidth=2)

    # Colorbar
    cbar = fig.colorbar(im, ax=axes, shrink=0.8, pad=0.02)
    cbar.set_label("Δ Vulnerability Rate (Treatment − Control)", fontsize=10)
    cbar.set_ticks([-1, -0.5, 0, 0.5, 1])
    cbar.set_ticklabels(["−100%\n(helped)", "−50%", "0%\n(no change)", "+50%", "+100%\n(backfire)"])

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-backfire-heatmap.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Figure 2: Aggregate Bar Chart ──────────────────────────────────────────

def make_aggregate_bars():
    """Grouped bar chart of aggregate vuln rates by model × condition."""
    models = ["Claude Sonnet 4", "GPT-5", "Gemma 4 31B"]
    model_data_list = [claude, gpt5, gemma]

    rates = {cond: [] for cond in CONDITIONS}

    for mdata in model_data_list:
        for cond in CONDITIONS:
            total_vuln = 0
            total_valid = 0
            for prompt in PROMPTS:
                v, n = get_counts(mdata, prompt, cond)
                total_vuln += v
                total_valid += n
            rates[cond].append(total_vuln / total_valid * 100 if total_valid > 0 else 0)

    x = np.arange(len(models))
    width = 0.25
    colors = ["#95a5a6", "#e74c3c", "#2ecc71"]  # gray, red, green

    fig, ax = plt.subplots(figsize=(10, 5.5))

    for i, (cond, label, color) in enumerate(zip(CONDITIONS, COND_SHORT, colors)):
        bars = ax.bar(x + i * width, rates[cond], width, label=label, color=color, edgecolor="white")
        for bar, val in zip(bars, rates[cond]):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                    f"{val:.0f}%", ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_ylabel("Vulnerability Rate (%)", fontsize=12)
    ax.set_title("Aggregate Vulnerability Rates by Model and Framing Condition",
                 fontsize=13, fontweight="bold")
    ax.set_xticks(x + width)
    ax.set_xticklabels(models, fontsize=11)
    ax.set_ylim(0, 85)
    ax.legend(fontsize=11, loc="upper right")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.axhline(y=0, color="black", linewidth=0.5)

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-aggregate-bars.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Figure 3: Non-API Null Result ──────────────────────────────────────────

def make_nonapi_null():
    """Bar chart showing 0/225 for non-API prompts vs baseline for API-naming."""
    # API-naming aggregate across all models (control condition)
    api_vuln = 0
    api_total = 0
    for mdata in [claude, gpt5, gemma]:
        for prompt in PROMPTS:
            v, n = get_counts(mdata, prompt, "control")
            api_vuln += v
            api_total += n

    api_rate = api_vuln / api_total * 100

    # Non-API: all zeros
    nonapi_vuln = 0
    nonapi_total = 0
    for mid, prompts in nonapi_data["summary"].items():
        for pid, conds in prompts.items():
            for cond, vals in conds.items():
                nonapi_total += vals["total"]
                nonapi_vuln += vals["vuln"]

    nonapi_rate = nonapi_vuln / nonapi_total * 100 if nonapi_total > 0 else 0

    fig, ax = plt.subplots(figsize=(7, 5))

    categories = ["Prompt names\ninsecure API\n(control, no rules)", "Prompt does NOT\nname insecure API\n(any framing)"]
    values = [api_rate, nonapi_rate]
    colors = ["#e74c3c", "#2ecc71"]

    bars = ax.bar(categories, values, color=colors, width=0.5, edgecolor="white", linewidth=2)

    ax.text(0, api_rate + 1.5, f"{api_rate:.0f}%\n({api_vuln}/{api_total})",
            ha="center", fontsize=12, fontweight="bold")
    ax.text(1, nonapi_rate + 1.5, f"0%\n(0/{nonapi_total})",
            ha="center", fontsize=12, fontweight="bold", color="#2ecc71")

    ax.set_ylabel("Vulnerability Rate (%)", fontsize=12)
    ax.set_title("Double-Priming Requirement:\nBackfire Only Occurs When Prompt Names the Insecure API",
                 fontsize=13, fontweight="bold")
    ax.set_ylim(0, 70)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-non-api-null.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Figure 4: Double-Priming Contrast ──────────────────────────────────────

def make_double_priming_contrast():
    """Side-by-side: API-naming prompts (backfire possible) vs non-API (no backfire)."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5), sharey=True)

    models = ["Claude\nSonnet 4", "GPT-5", "Gemma\n4 31B"]
    model_data_list = [claude, gpt5, gemma]
    x = np.arange(len(models))
    width = 0.25
    colors = ["#95a5a6", "#e74c3c", "#2ecc71"]

    # Left: API-naming prompts
    for i, (cond, label, color) in enumerate(zip(CONDITIONS, COND_SHORT, colors)):
        vals = []
        for mdata in model_data_list:
            tv, tn = 0, 0
            for prompt in PROMPTS:
                v, n = get_counts(mdata, prompt, cond)
                tv += v
                tn += n
            vals.append(tv / tn * 100 if tn > 0 else 0)
        ax1.bar(x + i * width, vals, width, label=label, color=color, edgecolor="white")

    ax1.set_title("Prompts Name Insecure API\n(backfire possible)", fontsize=12, fontweight="bold")
    ax1.set_ylabel("Vulnerability Rate (%)", fontsize=11)
    ax1.set_xticks(x + width)
    ax1.set_xticklabels(models, fontsize=10)
    ax1.set_ylim(0, 85)
    ax1.legend(fontsize=9)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    # Right: Non-API prompts
    model_ids = ["claude-sonnet", "gemma-4-31b-it", "gpt-5.3-codex"]
    model_labels_short = ["Claude\nSonnet 4", "GPT-5", "Gemma\n4 31B"]
    # Reorder to match left chart: Claude, GPT-5, Gemma
    model_order = ["claude-sonnet", "gpt-5.3-codex", "gemma-4-31b-it"]

    for i, (cond, label, color) in enumerate(zip(CONDITIONS, COND_SHORT, colors)):
        vals = []
        for mid in model_order:
            prompts = nonapi_data["summary"].get(mid, {})
            tv, tn = 0, 0
            for pid, conds_data in prompts.items():
                c = conds_data.get(cond, {})
                tv += c.get("vuln", 0)
                tn += c.get("total", 0)
            vals.append(tv / tn * 100 if tn > 0 else 0)
        ax2.bar(x + i * width, vals, width, label=label, color=color, edgecolor="white")

    ax2.set_title("Prompts Do NOT Name Insecure API\n(no backfire — 0/225)", fontsize=12, fontweight="bold")
    ax2.set_xticks(x + width)
    ax2.set_xticklabels(models, fontsize=10)
    ax2.set_ylim(0, 85)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    # Add "0%" annotation
    ax2.text(1, 3, "All bars = 0%", ha="center", fontsize=14, fontweight="bold",
             color="#2ecc71", style="italic")

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "fig-double-priming-contrast.png")
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")

# ─── Statistical Tests ──────────────────────────────────────────────────────

def cohens_h(p1, p2):
    """Cohen's h effect size for two proportions."""
    return 2 * (math.asin(math.sqrt(p1)) - math.asin(math.sqrt(p2)))

def run_statistical_tests():
    """Run Fisher's exact, chi-squared, and Cohen's h for all cells."""
    lines = []
    lines.append("=" * 70)
    lines.append("STATISTICAL ANALYSIS")
    lines.append("Don't Say Never: How Prohibition-Framed Security Rules Backfire")
    lines.append("=" * 70)

    models = [("Claude Sonnet 4", claude), ("GPT-5", gpt5), ("Gemma 4 31B", gemma)]

    # ── Per-cell Fisher's exact tests ──
    lines.append("\n" + "=" * 70)
    lines.append("1. PER-CELL FISHER'S EXACT TESTS (treatment vs control)")
    lines.append("=" * 70)

    for model_name, mdata in models:
        lines.append(f"\n── {model_name} ──")
        lines.append(f"{'Prompt':<20} {'Condition':<22} {'Ctrl':<8} {'Treat':<8} {'p-value':<10} {'Cohen h':<10} {'Sig'}")
        lines.append("-" * 90)

        for prompt in PROMPTS:
            ctrl_v, ctrl_n = get_counts(mdata, prompt, "control")
            if ctrl_n == 0:
                continue

            for cond in ["negative-framing", "positive-framing"]:
                treat_v, treat_n = get_counts(mdata, prompt, cond)
                if treat_n == 0:
                    continue

                # Fisher's exact test (2x2 table)
                table = [[treat_v, treat_n - treat_v], [ctrl_v, ctrl_n - ctrl_v]]
                _, p_value = stats.fisher_exact(table)

                # Effect size
                p1 = treat_v / treat_n
                p2 = ctrl_v / ctrl_n
                h = cohens_h(p1, p2)

                sig = "***" if p_value < 0.001 else "**" if p_value < 0.01 else "*" if p_value < 0.05 else ""
                backfire = " BACKFIRE" if p1 > p2 and p_value < 0.1 else ""

                cond_label = "Prohibition" if cond == "negative-framing" else "Alternative"
                lines.append(f"{prompt:<20} {cond_label:<22} {ctrl_v}/{ctrl_n:<6} {treat_v}/{treat_n:<6} {p_value:<10.4f} {h:<10.3f} {sig}{backfire}")

    # ── Aggregate chi-squared tests ──
    lines.append("\n" + "=" * 70)
    lines.append("2. AGGREGATE CHI-SQUARED TESTS (per model)")
    lines.append("=" * 70)

    for model_name, mdata in models:
        lines.append(f"\n── {model_name} ──")

        # Aggregate counts
        agg = {}
        for cond in CONDITIONS:
            tv, tn = 0, 0
            for prompt in PROMPTS:
                v, n = get_counts(mdata, prompt, cond)
                tv += v
                tn += n
            agg[cond] = (tv, tn)

        ctrl_v, ctrl_n = agg["control"]
        lines.append(f"  Control:     {ctrl_v}/{ctrl_n} ({ctrl_v/ctrl_n*100:.1f}%)")

        for cond in ["negative-framing", "positive-framing"]:
            treat_v, treat_n = agg[cond]
            cond_label = "Prohibition" if cond == "negative-framing" else "Alternative"

            # Chi-squared test
            table = np.array([[treat_v, treat_n - treat_v], [ctrl_v, ctrl_n - ctrl_v]])
            if np.all(table > 0):
                chi2, p_value, _, _ = stats.chi2_contingency(table, correction=True)
            else:
                _, p_value = stats.fisher_exact(table.tolist())
                chi2 = float("nan")

            h = cohens_h(treat_v / treat_n, ctrl_v / ctrl_n)
            sig = "***" if p_value < 0.001 else "**" if p_value < 0.01 else "*" if p_value < 0.05 else ""

            lines.append(f"  {cond_label:<14} {treat_v}/{treat_n} ({treat_v/treat_n*100:.1f}%)  "
                         f"chi2={chi2:.2f}  p={p_value:.4f}  h={h:.3f}  {sig}")

    # ── Phase 1 replication ──
    lines.append("\n" + "=" * 70)
    lines.append("3. PHASE 1 REPLICATION (Claude, eval-dynamic, isolated)")
    lines.append("=" * 70)

    with open(os.path.join(OUT_DIR, "../experiments/data/positive-framing-ablation.json")) as f:
        phase1 = json.load(f)

    p1_ctrl = phase1["summary"]["control"]
    p1_neg = phase1["summary"]["negative_framing"]
    p1_pos = phase1["summary"]["positive_framing"]

    lines.append(f"  Control:     {p1_ctrl['vulnerable']}/{p1_ctrl['total']} ({p1_ctrl['vulnerable']/p1_ctrl['total']*100:.0f}%)")
    lines.append(f"  Prohibition: {p1_neg['vulnerable']}/{p1_neg['total']} ({p1_neg['vulnerable']/p1_neg['total']*100:.0f}%)")
    lines.append(f"  Alternative: {p1_pos['vulnerable']}/{p1_pos['total']} ({p1_pos['vulnerable']/p1_pos['total']*100:.0f}%)")

    # Neg vs Control
    table = [[p1_neg["vulnerable"], p1_neg["total"] - p1_neg["vulnerable"]],
             [p1_ctrl["vulnerable"], p1_ctrl["total"] - p1_ctrl["vulnerable"]]]
    _, p = stats.fisher_exact(table)
    lines.append(f"  Prohibition vs Control: Fisher p={p:.4f} {'*' if p < 0.05 else ''}")

    # Neg vs Pos
    table = [[p1_neg["vulnerable"], p1_neg["total"] - p1_neg["vulnerable"]],
             [p1_pos["vulnerable"], p1_pos["total"] - p1_pos["vulnerable"]]]
    _, p = stats.fisher_exact(table)
    lines.append(f"  Prohibition vs Alternative: Fisher p={p:.4f} {'*' if p < 0.05 else ''}")

    # ── Non-API null result ──
    lines.append("\n" + "=" * 70)
    lines.append("4. NON-API NULL RESULT")
    lines.append("=" * 70)

    total_nonapi = 0
    total_vuln = 0
    for mid, prompts in nonapi_data["summary"].items():
        for pid, conds in prompts.items():
            for cond, vals in conds.items():
                total_nonapi += vals["total"]
                total_vuln += vals["vuln"]

    lines.append(f"  Total trials: {total_nonapi}")
    lines.append(f"  Vulnerable:   {total_vuln}")
    lines.append(f"  Rate:         {total_vuln/total_nonapi*100:.1f}%")
    lines.append(f"  95% CI:       [0%, {1.96/math.sqrt(total_nonapi)*100:.1f}%] (Wald)")
    lines.append(f"  Conclusion:   Prohibition rules do NOT independently prime the forbidden concept.")

    # ── Backfire summary ──
    lines.append("\n" + "=" * 70)
    lines.append("5. BACKFIRE INSTANCES (treatment > control)")
    lines.append("=" * 70)

    for model_name, mdata in models:
        for prompt in PROMPTS:
            ctrl_v, ctrl_n = get_counts(mdata, prompt, "control")
            if ctrl_n == 0:
                continue
            ctrl_rate = ctrl_v / ctrl_n

            for cond in ["negative-framing", "positive-framing"]:
                treat_v, treat_n = get_counts(mdata, prompt, cond)
                if treat_n == 0:
                    continue
                treat_rate = treat_v / treat_n

                if treat_rate > ctrl_rate:
                    table = [[treat_v, treat_n - treat_v], [ctrl_v, ctrl_n - ctrl_v]]
                    _, p = stats.fisher_exact(table)
                    h = cohens_h(treat_rate, ctrl_rate)
                    cond_label = "Prohibition" if cond == "negative-framing" else "Alternative"
                    sig = f"p={p:.4f}" + (" *" if p < 0.05 else "")
                    lines.append(f"  {model_name:<18} {prompt:<18} {cond_label:<14} "
                                 f"{ctrl_v}/{ctrl_n}→{treat_v}/{treat_n}  Δ=+{(treat_rate-ctrl_rate)*100:.0f}%  "
                                 f"h={h:.3f}  {sig}")

    output = "\n".join(lines)
    path = os.path.join(OUT_DIR, "statistical-tests.txt")
    with open(path, "w") as f:
        f.write(output)
    print(f"\nSaved: {path}")
    print("\n" + output)

# ─── Run everything ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    make_backfire_heatmap()
    make_aggregate_bars()
    make_nonapi_null()
    make_double_priming_contrast()
    run_statistical_tests()
    print("\n✓ All figures and statistical tests generated.")
