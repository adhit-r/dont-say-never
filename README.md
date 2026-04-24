# Rules Work, Polarity Doesn't: A Multi-Model Replication of Security Rule Framing Effects in LLM Coding Agents

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19509466.svg)](https://doi.org/10.5281/zenodo.19509466)

**Author:** [Adhithya Rajasekaran](https://orcid.org/0009-0004-1682-7958) (adhithya@axonome.xyz)

**Pilot paper:** [Don't Say Never (Zenodo)](https://doi.org/10.5281/zenodo.19509466) — superseded by the present replication.

## TL;DR

System-prompt security rules ("NEVER use eval()" or "Always use JSON.parse()") reliably reduce vulnerable code generation across 6 LLMs — but whether you phrase the rule as a prohibition or an alternative suggestion makes no consistent difference. The popular intuition that prohibition framing backfires (Wegner's ironic-process theory applied to LLMs) does not replicate at scale.

## Key Findings

| # | Finding | Evidence |
|---|---------|----------|
| 1 | **Rule injection works.** | Control baselines of 45–87% fall to 0–38% under either framing. Fisher's exact p < 0.001 in all 6 models; Cohen's h = 0.37–1.54. |
| 2 | **Polarity doesn't matter in the predicted direction.** | In 5/6 models, positive framing is statistically equal to or *worse* than negative. Only Haiku 4.5 trends in the Wegner-predicted direction (non-significantly). |
| 3 | **One model shows a significant reversal.** | Gemma 4 31B: negative 14.2%, positive 38.3% (p < 0.001). "Always use `https://`" produces *more* plaintext `http://` code than "never use `http://`". |
| 4 | **The pilot's backfire does not replicate.** | Across 36 (model, prompt) cells, no cell reproduces the pilot's 50%-vs-20% prohibition backfire. |

## Experimental Design

- **Models (6):** Claude Opus 4.6, Claude Sonnet 4.6, Claude Haiku 4.5, Claude Opus 4.1, Gemma 4 31B, GPT-5.4 Mini
- **Prompts (6):** eval-usage, md5-hash, http-url, insecure-random, eval-dynamic, weak-hash
- **CWE classes (4):** CWE-94 (code injection), CWE-328 (weak hash), CWE-319 (cleartext HTTP), CWE-338 (weak PRNG)
- **Conditions (3):** control (no rule), negative framing ("NEVER use X"), positive framing ("Always use Y")
- **Trials:** 20 per cell → ideal n = 2,160; valid n = 2,004 after filtering error-outs

## Figures

| Figure | Description |
|--------|-------------|
| ![Rule injection bars](figures/fig-rule-injection-bars.png) | Aggregate vulnerability rates by model × condition. Gray (control) towers over red (negative) and green (positive) in every model. |
| ![Polarity heatmap](figures/fig-polarity-heatmap.png) | Per-cell delta: positive − negative framing. Red = positive worse. No consistent blue (positive better) pattern. |
| ![Per-prompt grid](figures/fig-per-prompt-grid.png) | 6-panel breakdown showing prompt-level heterogeneity. |
| ![Baseline heatmap](figures/fig-control-baseline-heatmap.png) | Control (no-rule) baselines vary dramatically across models and prompts. |

## Repository Structure

```
paper/
  arxiv/          — LaTeX draft (paper.tex, abstract.txt, references.bib)
  aisec-ccs/      — Markdown draft for AISec @ CCS
  neurips-solar/  — Markdown draft for NeurIPS SoLaR
experiments/
  data/replication/  — 6-model JSON result files (2,004 valid trials)
  analysis/          — Statistical analysis output
  scripts/           — Orchestration script (comprehensive-replication.py)
figures/               — Generated PNGs + generation scripts
framing-templates/     — Negative vs positive framing rule templates
incidents/
  2026-04-15-copilot-quota/  — Data-collection incident documentation
```

## Reproducing

```bash
# Generate figures (requires python3 with matplotlib, scipy, numpy)
python3 figures/generate-replication-figures.py

# Run the full replication (requires API keys for Claude CLI, Gemini, OpenRouter)
python3 experiments/scripts/comprehensive-replication.py
```

## Submission Targets

- **AISec @ CCS 2026** — AI + Security workshop (Aug deadline)
- **NeurIPS SoLaR 2026** — Socially Responsible LLMs (Sep deadline)
- **TMLR** — Transactions on Machine Learning Research (rolling)

## Origin

This research emerged from [CodeCoach](https://github.com/axonome/patchpilot-codecoach) Experiment 7. A 645-trial pilot appeared to show prohibition-framed rules backfiring via Wegner's ironic-process theory. This repository contains the 3× scale replication that shows the effect does not generalise: rule injection is the robust finding, not framing polarity.

## License

Data and code: MIT. Paper drafts: CC-BY 4.0.
