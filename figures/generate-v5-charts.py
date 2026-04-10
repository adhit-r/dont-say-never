"""Generate updated charts for paper v5 with E2E v2 results (Semgrep SAST)."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

DPI = 300
COLORS = {'control': '#E74C3C', 'treatment': '#2ECC71', 'matched': '#3498DB', 'unmatched': '#95A5A6'}

# ── Fig 3: E2E Results by Model ──────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 4))
models = ['Claude Sonnet 4\n(n=54)', 'Nemotron 120B\n(hono only, n=18)', 'Overall\n(n=72)']
ctrl = [50.0, 100.0, 63.4]
treat = [22.2, 55.6, 29.3]

x = np.arange(len(models))
w = 0.32
bars1 = ax.bar(x - w/2, ctrl, w, label='Control (no rules)', color=COLORS['control'], alpha=0.85)
bars2 = ax.bar(x + w/2, treat, w, label='Treatment (PatchPilot rules)', color=COLORS['treatment'], alpha=0.85)

ax.set_ylabel('Vulnerability Rate (%)', fontsize=11)
ax.set_title('E2E Pipeline: Vulnerability Rates by Model', fontsize=12, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(models, fontsize=9)
ax.legend(fontsize=9)
ax.set_ylim(0, 115)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

# Add value labels
for bar in bars1:
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, f'{bar.get_height():.0f}%', ha='center', fontsize=9)
for bar in bars2:
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, f'{bar.get_height():.0f}%', ha='center', fontsize=9)

# Significance annotation
ax.annotate('54% reduction\nχ²=7.11, p<0.01', xy=(2, 29.3), xytext=(2.4, 65),
            fontsize=8, ha='center', arrowprops=dict(arrowstyle='->', color='black'),
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', edgecolor='gray'))

plt.tight_layout()
plt.savefig('figures/fig-e2e-results-v2.png', dpi=DPI, bbox_inches='tight')
print("Saved fig-e2e-results-v2.png")

# ── Fig 4: Matched vs Unmatched (Sonnet) ─────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 4))
cats = ['Matched CWEs\n(scanner rule exists)\nn=36', 'Unmatched CWEs\n(no scanner rule)\nn=17']
ctrl_m = [72.2, 0.0]
treat_m = [27.8, 11.1]

x = np.arange(len(cats))
bars1 = ax.bar(x - w/2, ctrl_m, w, label='Control', color=COLORS['control'], alpha=0.85)
bars2 = ax.bar(x + w/2, treat_m, w, label='Treatment', color=COLORS['treatment'], alpha=0.85)

ax.set_ylabel('Vulnerability Rate (%)', fontsize=11)
ax.set_title('Claude Sonnet 4: Matched vs Unmatched CWEs', fontsize=12, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(cats, fontsize=10)
ax.legend(fontsize=9)
ax.set_ylim(0, 100)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

for bar in bars1:
    if bar.get_height() > 0:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, f'{bar.get_height():.1f}%', ha='center', fontsize=9)
for bar in bars2:
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, f'{bar.get_height():.1f}%', ha='center', fontsize=9)

ax.annotate('62% reduction\nχ²=7.11, p<0.01', xy=(0, 27.8), xytext=(0.5, 55),
            fontsize=9, ha='center', arrowprops=dict(arrowstyle='->', color='black'),
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow', edgecolor='gray'))

ax.annotate('Sonnet already safe\n(0% baseline)', xy=(1, 0), xytext=(1.3, 35),
            fontsize=8, ha='center', color='gray', fontstyle='italic',
            arrowprops=dict(arrowstyle='->', color='gray'))

plt.tight_layout()
plt.savefig('figures/fig-matched-vs-unmatched-v2.png', dpi=DPI, bbox_inches='tight')
print("Saved fig-matched-vs-unmatched-v2.png")

# ── Fig 5: Per-Prompt Detail (Sonnet) ────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 5))

prompts = [
    ('md5-hash\n(CWE-328)', 3, 0, True),
    ('insecure-random\n(CWE-338)', 3, 0, True),
    ('weak-hash\n(CWE-328)', 3, 0, True),
    ('eval-usage\n(CWE-94)', 1, 0, True),
    ('http-url\n(CWE-319)', 3, 3, True),
    ('eval-dynamic\n(CWE-94)', 0, 2, True),
    ('sqli\n(CWE-89)', 0, 0, False),
    ('path-traversal\n(CWE-22)', 0, 0, False),
    ('cmd-injection\n(CWE-78)', 0, 1, False),
]

labels = [p[0] for p in prompts]
ctrl_vals = [p[1] for p in prompts]
treat_vals = [p[2] for p in prompts]
matched = [p[3] for p in prompts]

y = np.arange(len(prompts))
h = 0.35

for i in range(len(prompts)):
    c_color = COLORS['matched'] if matched[i] else COLORS['unmatched']
    ax.barh(y[i] + h/2, ctrl_vals[i], h, color=COLORS['control'], alpha=0.8)
    ax.barh(y[i] - h/2, treat_vals[i], h, color=COLORS['treatment'], alpha=0.8)
    # Add small marker for matched/unmatched
    marker = '●' if matched[i] else '○'
    ax.text(-0.3, y[i], marker, fontsize=10, ha='center', va='center',
            color=COLORS['matched'] if matched[i] else COLORS['unmatched'])

ax.set_yticks(y)
ax.set_yticklabels(labels, fontsize=8)
ax.set_xlabel('Vulnerable Trials (out of 3)', fontsize=10)
ax.set_title('Claude Sonnet 4: Per-Prompt Results (● = matched, ○ = unmatched)', fontsize=11, fontweight='bold')
ax.set_xlim(-0.5, 3.5)
ax.legend(['Control', 'Treatment'], fontsize=9, loc='lower right')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.invert_yaxis()

# Annotations for interesting cases
ax.annotate('prompt specifies\nexact URL', xy=(3, 4), fontsize=7, color='gray', fontstyle='italic')
ax.annotate('treatment\nworsened', xy=(2, 5), fontsize=7, color='red', fontstyle='italic')

plt.tight_layout()
plt.savefig('figures/fig-per-prompt-sonnet.png', dpi=DPI, bbox_inches='tight')
print("Saved fig-per-prompt-sonnet.png")

print("\nAll v5 charts generated.")
