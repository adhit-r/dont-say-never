# Project: LLM Framing Paper (Standalone Research)

This is a **standalone research paper repo** — NOT a software product. Do NOT confuse it with PatchPilot or CodeCoach.

## What this is

A research paper: **"Do Safety Rules Backfire? An Empirical Study of How Rule Framing Affects LLM Code Security"**

Author: Adhithya Rajasekaran

## What this is NOT

- This is NOT PatchPilot (the security scanner product)
- This is NOT CodeCoach (the AI agent coaching product)
- This is NOT a web app, API, or deployable system
- There is no frontend, backend, database, or deployment pipeline here

## Origin

This research originated from CodeCoach Experiment 7 (in the separate `patchpilot_codecoach` repo). The finding was significant enough to spin out as a standalone workshop paper. All materials have been copied here — this repo is fully independent.

## Repo structure

- `paper/` — Paper drafts (markdown, HTML, TeX, PDF). Latest is `paper-v4`
- `figures/` — Chart PNGs + Python generation scripts
- `experiments/data/` — Raw experiment results (JSON). Key files:
  - `positive-framing-ablation.json` — Phase 1: 30 trials, eval-dynamic paradox
  - `positive-framing-ablation-v2.json` — Phase 2: 180 trials, multi-prompt
  - `multi-model-results.json` — Cross-model comparison
- `experiments/scripts/` — TypeScript experiment scripts (run against LLM APIs)
- `experiments/generated-rules/` — CLAUDE.md/.cursorrules for 7 test repos
- `framing-templates/` — Negative vs positive framing rule templates

## Key findings

1. Prohibition framing ("NEVER use eval()") caused 50% vulnerable output vs 20% baseline on one prompt (p=0.016)
2. Positive framing ("Always use JSON.parse()") reduced it to 0%
3. The effect does NOT generalize across all prompts — it's prompt-specific
4. The dominant effect is rule injection itself (59% → 14-24% regardless of framing)
5. Double-priming hypothesis: effect concentrates when prompt names the same API the rule prohibits

## Tasks in this repo

- Writing/editing the paper (markdown or LaTeX)
- Running experiment scripts (TypeScript, require OpenRouter/Anthropic API keys)
- Generating charts (Python matplotlib)
- Analyzing experiment data (JSON files)

## Hard rules

- Do NOT add product code, web UI, or API endpoints to this repo
- Do NOT reference internal PatchPilot/CodeCoach implementation details in the paper
- Experiment scripts use OpenRouter API — never hardcode API keys
