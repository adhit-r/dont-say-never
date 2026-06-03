# Artifact Freeze Checklist

Date: 2026-06-03

This checklist defines what must be true before publishing a Zenodo v2 artifact for the reframed paper.

## Freeze Blockers

- [x] Source worktree was clean before freeze manifest generation.
- [x] Source commit hash is recorded in `ARTIFACT_COMMIT.txt`.
- [x] `LICENSE` exists and clarifies code/data and paper licensing.
- [x] `CITATION.cff` exists.
- [x] `.zenodo.json` exists.
- [x] Dependency/environment file exists (`requirements.txt`, `pyproject.toml`, or `environment.yml`).
- [x] `ARTIFACT_README.md` exists with reproduction commands and claim boundaries.
- [x] `experiments/data/pro-replication/control-baselines/` is clearly labeled partial.
- [x] `experiments/data/pro-replication/cross-language/gpt-5.3-codex.json` is labeled as route-error evidence only.
- [x] Four-arm add-on files are summarized as complete valid add-on rows with retained error rows disclosed.
- [x] `paper/arxiv/paper.pdf` is rebuilt from the current `paper.tex`.

## Include In Zenodo v2

- `README.md`
- `ARTIFACT_README.md`
- `ARTIFACT_COMMIT.txt`
- `SHA256SUMS`
- `LICENSE`
- `CITATION.cff`
- `.zenodo.json`
- `research/SUBMISSION_CHECKLIST.md`
- `research/REVIEWER_CRITIQUE_ACTION_PLAN.md`
- `research/STRENGTHENING_ROADMAP.md`
- `experiments/validation/functional-refusal/FUNCTIONAL_LABELING_GUIDE.md`
- `paper/arxiv/paper.tex`
- `paper/arxiv/paper.pdf`
- `paper/arxiv/abstract.txt`
- `paper/arxiv/references.bib`
- `experiments/data/pro-replication/main/`
- `experiments/data/pro-replication/non-api/`
- `experiments/data/pro-replication/four-arm-addons/`
- `experiments/data/pro-replication/cross-language/`
- `experiments/data/pro-replication/control-baselines/` if labeled partial
- `experiments/data/pro-replication/smoke-tests.json`
- `experiments/data/pro-replication/quota-ledger.jsonl`
- `experiments/data/pro-replication/openrouter-claude-ledger.jsonl`
- `experiments/validation/`
- `experiments/analysis/`
- `experiments/scripts/`
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
- `figures/generate-pro-replication-figures.py`
- `incidents/2026-04-15-copilot-quota/` only if the incident remains as appendix evidence

## Exclude From Bundle

- `.git/`
- `.claude/settings.local.json`
- `.playwright-mcp/`
- `.DS_Store`
- `__pycache__/`
- `paper/arxiv/Archive.zip` unless rebuilt and documented as the exact paper-source package

## Commands Before Freeze

```bash
cd /Users/adhi/axonome/llm-framing-paper
test -z "$(git status --porcelain=v1 --untracked-files=all)"
git rev-parse HEAD > ARTIFACT_COMMIT.txt
python3.11 experiments/scripts/pro-six-model-replication.py summary
python3.11 experiments/scripts/hierarchical-framing-stats.py
python3.11 experiments/scripts/summarize-non-api-extension.py
python3.11 experiments/scripts/summarize-four-arm-extension.py
python3.11 experiments/scripts/summarize-cross-language-extension.py
python3.11 experiments/scripts/summarize-control-baselines.py
python3.11 experiments/scripts/summarize-combined-detector-validation.py
python3.11 experiments/scripts/classify-functional-refusal-validation.py
python3.11 figures/generate-pro-replication-figures.py
find README.md ARTIFACT_README.md ARTIFACT_FREEZE_CHECKLIST.md ARTIFACT_COMMIT.txt LICENSE CITATION.cff .zenodo.json requirements.txt research paper/arxiv experiments/data/pro-replication experiments/validation experiments/analysis experiments/scripts figures incidents/2026-04-15-copilot-quota -type f \
  ! -path '*/__pycache__/*' ! -name '.DS_Store' ! -path 'paper/arxiv/Archive.zip' \
  -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS
```

## Zenodo Metadata

- Title: `Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing`
- Creator: `Adhithya Rajasekaran`
- ORCID: `0009-0004-1682-7958`
- Relation: supersedes pilot DOI `10.5281/zenodo.19509466`
- License: split code/data vs paper if needed
- Notes:
  - main 2,160-row JSON preserves `code_preview`, not full generated outputs;
  - full-output validation is a 60-row rerun slice with manual functional labels;
  - control-baseline extension is partial;
  - cross-language GPT-5.3 Codex file is route-error evidence only.
