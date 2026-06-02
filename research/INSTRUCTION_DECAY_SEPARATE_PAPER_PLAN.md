# Instruction-Decay Follow-Up Paper Plan

## Working Title

When Remembering Is Not Enough: Instruction Decay Over Long Agentic Contexts

## Status

Separate-paper candidate. Do not expand the main security-rule framing paper around this topic.

## Motivation

The current paper contains a single documented incident: an AI coding agent violated a conversational budget constraint after 70 turns and roughly 54k intervening tokens. That case is useful as an existence proof, but it is not enough for a general claim.

## Core Hypothesis

Instructions stated once in chat decay as effective behavioral constraints as unrelated context accumulates, even when the instruction remains inside the nominal context window.

## Minimal Experiment

- Models: 2-3 coding agents.
- Constraint: one explicit budget/tool-routing rule stated once.
- Distance levels: 0, 10, 30, 60, 100 intervening turns.
- Refresh condition: no refresh vs periodic reminder vs persistent file rule.
- Task: choose a route among cheap/free/premium model APIs under a fixed budget.
- Outcome: whether the selected route violates the constraint.

## Design

2 models x 5 distances x 3 refresh conditions x 20 trials = 600 trials.

## Measures

- Violation rate.
- Whether the model mentions the constraint.
- Whether the model chooses a compliant route.
- Latency and token use.
- Qualitative failure mode: forgot, noticed but overrode, miscomputed, or misrouted.

## Claim Boundary

This would test conversational instruction decay, not security-rule polarity. It should be submitted as an instruction-following or agent-governance paper, with the current Copilot quota incident as motivating evidence only.

## Reuse From Current Repo

- `incidents/2026-04-15-copilot-quota/`
- budget/quota ledger patterns
- model-routing scripts
- AI-use disclosure language

