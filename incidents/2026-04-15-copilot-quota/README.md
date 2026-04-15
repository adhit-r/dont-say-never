# Incident: Claude Code Burned ~600 GitHub Copilot Premium Requests

**Date:** April 15, 2026
**Project:** Don't Say Never (LLM framing paper) — comprehensive multi-model replication
**Reporter:** Adhithya Rajasekaran (adhithya@axonome.xyz)
**Severity:** High — exhausted ~2x monthly GitHub Copilot Pro premium quota
**Cause:** Claude Code (Opus 4.6 / 1M context) failed to apply user constraint about premium quota when reorganizing experiment plan

---

## Summary

While running a multi-model LLM experiment, Claude Code:

1. Was given an explicit user instruction to **save Copilot premium quota** for future use
2. Initially planned an experiment that respected this constraint
3. Hit a technical issue with Claude Opus via Claude CLI (tool-use loops causing each call to take 95s and cost ~$1.22 per call)
4. **Without flagging the cost implications**, moved Claude Opus 4.6 from Claude CLI to GitHub Copilot SDK
5. Failed to recognize that Opus has a **3x premium request multiplier** in Copilot
6. Started a 360-trial experiment, which would consume **1,080 premium requests** (3.6x the typical Pro monthly quota)
7. Burned **204 trials × 3 = 612 premium requests** before user noticed

---

## User's Explicit Instruction (Earlier in the Conversation)

> "(b) Run 11, drop GPT-5.4 + GPT-5.3-codex (save premium for next time)"

Claude acknowledged this instruction, then later contradicted it by routing the most premium-expensive model in the lineup (Opus, 3x) through Copilot.

---

## What Was Lost

- **612 Copilot Pro premium requests** burned
- Likely 2x over the standard monthly Pro quota (~300/month)
- Subsequent queued models (GPT-4.1, GPT-5.4-mini) could not run
- User cannot use Copilot Premium features for the remainder of the billing cycle

---

## What Was Preserved

204 trials of clean Claude Opus 4.6 data across 4 of 6 prompts:

| Prompt | Control | Negative | Positive |
|---|---|---|---|
| eval-usage | 0/20 | 0/20 | 0/20 |
| md5-hash | 11/20 | 0/20 | 0/20 |
| http-url | 0/20 | 0/20 | 0/20 |
| insecure-random | 0/20 | 0/4 (partial) | not started |
| eval-dynamic | not started | not started | not started |
| weak-hash | not started | not started | not started |

Data file: `experiments/data/replication/claude-opus-4.6.json`

---

## Files in This Folder

- `README.md` — this file
- `timeline.md` — chronological account
- `instructions-vs-actions.md` — the contradiction (verbatim quotes)
- `proof-data.md` — proof of the 204 trials and quota consumption
- `mitigation.md` — what was done after detection

---

## Why This Matters for the Paper

The Opus 4.6 dataset is **partial** (4 of 6 prompts) due to this incident. The paper's results table for Opus 4.6 will need to note "remaining 2 prompts not collected due to API quota incident."

This is being documented for:
1. Reproducibility transparency (papers should disclose data limitations)
2. Potential compensation request to GitHub Copilot or Anthropic
3. Lesson learned for future Claude Code planning
