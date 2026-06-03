# Artifact README

This artifact supports the paper:

**Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing**

Author: Adhithya Rajasekaran, Axonome, ORCID `0009-0004-1682-7958`

Repository: `https://github.com/adhit-r/dont-say-never`

Prior pilot DOI, to be linked from Zenodo v2 with `isNewVersionOf`: `10.5281/zenodo.19509466`

## Claim Boundary

Supported by the current artifact:

- targeted CWE-specific security rules reduce detector-counted insecure API use in the main 2,160-row benchmark;
- positive framing has no consistent aggregate advantage over prohibition framing in the tested benchmark;
- exploratory per-cell effects are heterogeneous and should be interpreted with multiple-testing correction;
- the non-API extension shows prompt-class-dependent behavior in this prompt set;
- the four-arm extension is consistent with an information-content explanation; valid add-on rows are complete and retained error rows are disclosed in the summary.

Not supported without further work:

- positive and negative framing are equivalent;
- rules make coding agents generally secure;
- non-vulnerable outputs are necessarily functional;
- the original fast-prototyping control proves ordinary coding-agent improvement;
- the instruction-decay incident is a general result.

## Artifact Map

Main paper:

- `paper/arxiv/paper.tex`
- `paper/arxiv/paper.pdf`
- `paper/arxiv/abstract.txt`
- `paper/arxiv/references.bib`

Main replication:

- `experiments/data/pro-replication/main/`
- `experiments/scripts/pro-six-model-replication.py`
- `experiments/analysis/hierarchical-framing-stats.md`
- `experiments/analysis/hierarchical-framing-stats.json`

Extensions:

- `experiments/data/pro-replication/non-api/`
- `experiments/data/pro-replication/four-arm-addons/`
- `experiments/data/pro-replication/cross-language/`
- `experiments/data/pro-replication/control-baselines/` (partial)
- `experiments/analysis/non-api-extension-summary.md`
- `experiments/analysis/four-arm-extension-summary.md`
- `experiments/analysis/cross-language-extension-summary.md`
- `experiments/analysis/control-baselines-summary.md`

Validation:

- `experiments/validation/detector-validation-combined-summary.md`
- `experiments/validation/reruns/`
- `experiments/validation/openrouter-claude-reruns/`
- `experiments/validation/functional-refusal/`

Figures:

- `figures/fig-pro-gpt-vs-claude-bars.png`
- `figures/fig-pro-polarity-heatmap.png`
- `figures/fig-pro-control-baseline-heatmap.png`
- `figures/fig-pro-non-api-control.png`
- `figures/fig-four-arm-decomposition.png`
- `figures/fig-four-arm-model-heatmap.png`
- `figures/fig-rule-design-takeaway.png`
- `figures/fig-evidence-stack-infographic.png`
- `figures/fig-pro-cross-language.png`
- `figures/fig-control-baselines.png`

Incident evidence, if retained in the manuscript appendix:

- `incidents/2026-04-15-copilot-quota/`

## Reproduction Commands

Use Python 3.11. Install the small Python dependency set:

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

These requirements reproduce analysis summaries and figures only. Re-running model collection additionally requires Codex CLI, Claude CLI or OpenRouter credentials, and Node/TypeScript tooling for legacy scripts; model collection is not part of the frozen reproduction path.

Regenerate analysis summaries:

```bash
python3.11 experiments/scripts/pro-six-model-replication.py summary
python3.11 experiments/scripts/hierarchical-framing-stats.py
python3.11 experiments/scripts/summarize-non-api-extension.py
python3.11 experiments/scripts/summarize-four-arm-extension.py
python3.11 experiments/scripts/summarize-cross-language-extension.py
python3.11 experiments/scripts/summarize-control-baselines.py
python3.11 experiments/scripts/summarize-combined-detector-validation.py
python3.11 experiments/scripts/classify-functional-refusal-validation.py
python3.11 figures/generate-pro-replication-figures.py
```

Build the paper PDF if `tectonic` is installed:

```bash
cd paper/arxiv
tectonic paper.tex
```

## Known Limitations

- The main 2,160-row JSON files preserve `code_preview`, not full generated outputs.
- Full-output validation is a 60-row rerun slice and does not retroactively make the full main dataset auditable.
- Functional/refusal validation includes manual task-satisfaction labels for the 60-row full-output validation slice: 34 secure+functional, 20 vulnerable+functional, 4 secure+nonfunctional, and 2 refusal/no-code.
- TypeScript compile checks are marked `not_run` when `tsc` is unavailable.
- Control-baseline data are partial unless the extension is completed before final release.
- Cross-language GPT-5.3 Codex rows are route-error evidence only.
- Claude-family extension data that used OpenRouter should be interpreted with route-confound caution.
