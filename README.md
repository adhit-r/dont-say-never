# Don't Say Never: How Prohibition-Framed Security Rules Backfire in LLM Coding Agents

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19509466.svg)](https://doi.org/10.5281/zenodo.19509466)

**Author:** [Adhithya Rajasekaran](https://orcid.org/0009-0004-1682-7958) (adhithya@axonome.xyz)

**Paper:** [Zenodo](https://doi.org/10.5281/zenodo.19509466) | [OpenAIRE](https://explore.openaire.eu/search/result?pid=10.5281%2Fzenodo.19509466) | [ORCID](https://orcid.org/0009-0004-1682-7958)

> **Origin:** This research emerged from [CodeCoach](https://github.com/axonome/patchpilot-codecoach), an AI agent coaching system built on top of PatchPilot (security scanner). During Experiment 7 of the CodeCoach evaluation, we discovered that prohibition-framed safety rules ("NEVER use eval()") paradoxically increased the probability of the unsafe behavior on certain prompts. This standalone paper isolates and investigates that finding.

## Research Question

When LLM coding agents receive system-prompt safety rules, does phrasing those rules as prohibitions ("NEVER use eval()") paradoxically increase the probability of the unsafe behavior compared to alternative-suggestion framing ("Always use JSON.parse()")?

## Hypothesis

Grounded in Wegner's Ironic Process Theory (1994): actively suppressing a thought requires a monitoring process that keeps the thought accessible. If this transfers to LLM token distributions, prohibition-framed rules that name the unsafe API may shift probability mass toward that API — especially when the user prompt also names it (double priming).

## Status

### Done (from CodeCoach Experiment 7)
- [x] Phase 1: single-prompt isolation on eval-dynamic (30 trials, Sonnet 4)
  - Control 20%, Negative 50%, Positive 0% — p=0.016 (Fisher's exact)
- [x] Phase 2: multi-prompt generalization (180 trials, 6 prompts, Sonnet 4)
  - Aggregate: Control 59%, Negative 14%, Positive 24%
  - Framing effect is prompt-specific, not systematic
  - Rule injection itself is the dominant effect (both framings p<0.001 vs control)

### TODO for standalone paper
- [ ] **Multi-model replication** (highest priority)
  - Run Phase 1 (eval-dynamic, 10 trials × 3 conditions) on:
    - [ ] GPT-4o (via OpenRouter or direct API)
    - [ ] Gemini 2.5 Pro (via Google AI Studio API)
    - [ ] Llama 3.1 70B (via OpenRouter)
  - Script: `scripts/multi-model-framing.ts` (to be written)
  - Estimated cost: ~$5-10 total (30 calls × 3 models)
  
- [ ] **Broader prompt set** (medium priority)
  - Add 10+ prompts beyond the 6 E2E prompts
  - Include prompts that DON'T name the insecure API (pure priming test)
  - Include prompts from other languages (Python eval, Go exec)
  
- [ ] **Token-level analysis** (if API supports logprobs)
  - Compare P(eval) token probability under negative vs positive framing
  - This would give mechanistic evidence, not just behavioral
  
- [x] **Paper draft** (4-8 pages, workshop format)
  - [x] Introduction + Wegner theory background
  - [x] Methodology (clear experiment design)
  - [x] Results (Phase 1 + Phase 2 + multi-model + broader prompts)
  - [x] Discussion (when does framing matter? double-priming hypothesis)
  - [x] Limitations
  
- [ ] **Submission targets** (ordered by deadline)
  - AISEC @ CCS 2026 (AI + Security workshop, ~Aug deadline)
  - SCORED @ CCS 2026 (Software supply chain, ~Aug deadline)
  - NeurIPS SoLaR 2026 (Socially responsible LLMs, ~Sep deadline)
  - EMNLP Safety Workshop 2026 (~Sep deadline)

## Data Inventory

All existing data from CodeCoach Experiment 7:

| File | Description |
|------|-------------|
| `data/phase1-eval-dynamic.json` | Phase 1: 30 trials (symlink to parent) |
| `data/phase2-multi-prompt.json` | Phase 2: 180 trials (symlink to parent) |
| `data/framing-templates/` | CLAUDE.md sections used in each condition |
| `scripts/multi-model-framing.ts` | Multi-model replication script (TODO) |
| `paper/framing-paper.tex` | Paper draft (workshop format, LaTeX) |

## Key Findings Summary

1. **Eval-dynamic paradox is real** — negative framing (50%) is worse than no rules (20%) on this specific prompt
2. **Positive framing mitigates it** — 0/10 vulnerable on eval-dynamic (p=0.016)
3. **Effect does NOT generalize** — across 6 prompts, both framings are equivalent (p=0.73)
4. **weak-hash is a counterexample** — negative framing 0/10, positive 3/10 (opposite direction)
5. **The dominant effect is rule injection itself** — 59% → 14-24% regardless of framing
6. **http-url is a different failure mode** — explicit API in prompt overrides any system rule

## Paper Angle

Not "positive framing is always better" (disproven by our own data). Instead:

**"When do safety rules backfire?"** — An empirical characterization of the conditions under which prohibition-framed rules increase unsafe behavior, with evidence that the effect concentrates on prompts that name the same API the rule prohibits (double priming). The practical recommendation: use alternative-suggestion framing for rules where the CWE involves a specific API name (eval, exec), and either framing for rules where the CWE involves a pattern (weak hash, insecure random).
