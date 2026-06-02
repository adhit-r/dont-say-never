# Control-Baseline Extension Plan

Date: 2026-06-02

## Purpose

This extension addresses the strongest methodology critique of the current paper:

> The original control condition says "Do not add extra validation or security measures unless asked." Therefore, the rule effect may partly measure override of an anti-security fast-prototyping instruction rather than improvement over ordinary coding-agent behavior.

## Experimental Question

Do targeted CWE-specific persistent rules reduce insecure API use compared with:

1. an adversarial fast-prototyping control;
2. a neutral helpful-assistant control;
3. a generic secure-coding control?

## Conditions

The original main-suite `control` is retained and renamed analytically:

- `fast-prototype-control`: original control; discourages extra security unless asked.

Two new conditions are added under the `control-baselines` suite:

- `neutral-control`: helpful coding assistant; no security discouragement.
- `generic-security-control`: broad secure-coding instruction; no CWE-specific rule.

The strongest targeted-rule comparator is reused from the completed four-arm extension:

- `targeted-combined-rule`: concrete CWE-specific prohibition plus safe replacement.

## Design

New rows:

```text
6 models x 6 prompts x 2 new controls x 20 trials = 1,440 rows
```

Reused rows:

```text
fast-prototype-control: 720 rows from experiments/data/pro-replication/main/
targeted-combined-rule: 720 rows from experiments/data/pro-replication/four-arm-addons/
```

## Runner

Use:

```bash
python3.11 experiments/scripts/pro-six-model-replication.py run \
  --suite control-baselines \
  --cells-per-run 6 \
  --max-attempts 140 \
  --max-cost-usd 3
```

Run in small batches. The suite is resumable and writes:

```text
experiments/data/pro-replication/control-baselines/
```

## Summary

After any batch:

```bash
python3.11 experiments/scripts/summarize-control-baselines.py
```

This writes:

```text
experiments/analysis/control-baselines-summary.md
figures/fig-control-baselines.png
```

## Claim Boundary

If targeted rules beat all three controls:

> CWE-specific persistent rules improve security beyond generic secure-coding advice.

If targeted rules only beat fast-prototyping control:

> Rule effects are real in adversarial fast-prototyping contexts, but weaker under neutral or generic-security baselines.

If generic secure coding matches targeted rules:

> The important factor may be explicit security salience rather than CWE-specific rule content.

## Stop Rule

Pause the suite if:

- any model hits repeated route errors;
- a provider starts silently substituting model IDs;
- quota/cost behavior deviates from the ledger;
- the first 20-trial cell shows the prompt is malformed or not comparable.

