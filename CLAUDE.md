# Project: LLM Framing Paper (Standalone Research)

This is a **standalone research paper repo** — NOT a software product. Do NOT confuse it with PatchPilot or CodeCoach.

## What this is

A research paper: **"Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing"**

Author: Adhithya Rajasekaran

## What this is NOT

- This is NOT PatchPilot (the security scanner product)
- This is NOT CodeCoach (the AI agent coaching product)
- This is NOT a web app, API, or deployable system
- There is no frontend, backend, database, or deployment pipeline here

## Origin

This research originated from CodeCoach Experiment 7 (in the separate `patchpilot_codecoach` repo). A narrow pilot anomaly was significant enough to spin out as a standalone paper. The larger replication supersedes the pilot framing; this repo is fully independent.

## Repo structure

- `paper/` — Paper drafts (markdown, TeX, PDF). Latest archival draft is `paper/arxiv/paper.tex`
- `figures/` — Chart PNGs + Python generation scripts
- `experiments/data/pro-replication/main/` — Final 2,160-row six-model replication
- `experiments/data/pro-replication/non-api/` — Completed 1,080-row non-API extension
- `experiments/data/pro-replication/four-arm-addons/` — Completed four-arm decomposition add-ons
- `experiments/data/pro-replication/control-baselines/` — Partial neutral/generic control extension
- `experiments/validation/` — Full-output detector and functional/refusal validation slices
- `experiments/scripts/` — Experiment and analysis scripts

## Key findings

1. Targeted security rules reduce detector-counted insecure API use across all six tested coding agents.
2. Positive framing has no consistent aggregate advantage over prohibition framing in the main 2,160-row benchmark.
3. The pilot 5/10 vs 2/10 backfire cell was over-interpreted; Fisher's exact test is two-sided p approx. 0.350, not p=0.016.
4. Four-arm decomposition suggests information content matters more than polarity: combined rules are strongest overall.
5. Non-API prompts are prompt-class dependent: formula evaluation remains high-risk without naming `eval()`, while hash/token prompts are inert in this prompt set.

## Tasks in this repo

- Writing/editing the paper (markdown or LaTeX)
- Running experiment scripts (Python/Codex/OpenRouter/Claude routes depending on suite)
- Generating charts (Python matplotlib)
- Analyzing experiment data (JSON files)

## Hard rules

- Do NOT add product code, web UI, or API endpoints to this repo
- Do NOT overclaim beyond detector-counted insecure API use and bounded validation slices
- Do NOT describe positive and negative framing as equivalent unless equivalence testing is added
- Never hardcode API keys
