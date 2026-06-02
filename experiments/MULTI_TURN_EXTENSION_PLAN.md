# Multi-Turn Agent Workflow Extension Plan

## Status

Planned. Not yet run.

## Purpose

Test whether the rule-presence effect survives a small draft-review-revise workflow, rather than only single-turn code generation.

## Minimal Design

- Models: start with 2 stable routes.
  - GPT-5.4 via Codex CLI.
  - Claude Sonnet 4.6 via OpenRouter.
- Prompts: `insecure-random`, `weak-hash`, optionally `eval-dynamic`.
- Conditions: control vs rules-present.
- Trials: 10 conversations per prompt-condition-model.
- Turns per conversation:
  1. Draft implementation.
  2. Review and fix security issues.
  3. Final cleaned implementation.

For 2 prompts: 2 models x 2 prompts x 2 conditions x 10 conversations x 3 turns = 240 assistant turns.

## Metrics

- First-turn vulnerable.
- Final-turn vulnerable.
- Recovered: first vulnerable, final safe.
- Regressed: first safe, final vulnerable.
- Refusal/no-code rate.

## Runner Requirements

- New isolated runner, not the single-turn runner.
- Save one JSON row per assistant turn.
- Include `conversation_id`, `turn`, `stage`, `condition`, `prompt_id`, `model_id`.
- Score extracted code only; ignore review prose.
- Preserve full raw responses.

## Claim Boundary

This extension supports ecological validity for agentic coding workflows. It should not be pooled with the main single-turn replication and should not be used to revive the polarity hypothesis.

