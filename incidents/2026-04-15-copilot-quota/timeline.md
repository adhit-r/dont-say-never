# Chronological Timeline

## Setup phase (planning)

**~22:00 PDT 2026-04-14:** User asked Claude Code to design comprehensive multi-model replication of the framing experiment.

**Claude proposed:** 13 models across 4 APIs (Claude CLI, Copilot SDK, Gemini API, OpenRouter).

**Claude listed Copilot premium costs explicitly:**
> Premium consumption per full run (6 prompts × 3 conditions × 20 trials = 360 calls per model):
> - gpt-5.4: 360 premium requests
> - gpt-5.3-codex: 360 premium requests
> - gpt-5.4-mini: 120 premium requests
> - claude-haiku-4.5: 360 premium requests (0x = none if Haiku is free)
> - **Total: ~1,200 premium requests** if you have Pro+ (300 premium/mo) you'd burn through them in one run

Claude offered options including:
> **(b)** Run 11, drop GPT-5.4 + GPT-5.3-codex (save premium for next time)

**User selected (b):** "(b) Run 11, drop GPT-5.4 + GPT-5.3-codex (save premium for next time)"

User clearly intended to **save premium quota for next time**.

---

## First run (correct plan)

Initial MODELS list per user's choice (b):
- Anthropic via Claude CLI: Opus 4.6, Sonnet 4.6
- Anthropic + OpenAI via Copilot SDK: Haiku 4.5 (0x), GPT-4.1 (0x), GPT-5.4-mini (0.33x)
- Google via Gemini API: Gemini 2.5 Pro, Flash, Gemma 4 31B
- 4 OpenRouter free models

Total premium expected: Haiku (0) + GPT-4.1 (0) + GPT-5.4-mini (~120) = **~120 premium**.

Within the user's preferred budget.

---

## The mistake

Claude ran the experiment. Multiple issues emerged:
- Gemini 2.5 Pro returned 429 (paid-only)
- OpenRouter free models returned 100% errors
- **Claude Opus 4.6 via Claude CLI got stuck in tool-use loops** — each call took 95s, used 20 turns, and would have cost the equivalent of $1.22 per call

Claude's reasoning at this point (visible in transcript):
> "Opus via Claude CLI is broken — it's going into tool-use loops (20 turns per call, 95 seconds each, $1.22/call). Claude CLI resolves `opus` to the old Opus 4.1 model which defaults to tool use."

**Claude's solution:**
> "Let me kill all batches, restructure, and restart"

Claude moved Opus 4.6 from Claude CLI to **Copilot SDK** without recalculating premium consumption.

The new MODELS configuration (in script):
```python
{"id": "claude-opus-4.6", "name": "Claude Opus 4.6", "api": "copilot", "copilot_id": "claude-opus-4.6"},
```

This change added **3x × 360 = 1,080 premium requests** to the budget. Claude did NOT flag this to the user. Claude did NOT recalculate against the user's stated budget concern.

---

## Detection

User noticed Copilot showing 100% premium usage and asked:
> "how did you manage to exhaust 100% usage of copilot?"

Claude immediately recognized the mistake:
> "That's on me — I made a critical mistake. When I moved Opus 4.6 from Claude CLI to Copilot SDK to fix the tool-loop bug, I forgot Opus is 3x premium multiplier in Copilot."

Claude killed the Copilot batch. Damage was already done.

---

## Damage assessment

By the time Copilot batch was killed:
- **204 Opus 4.6 trials saved** = 612 premium requests consumed
- This is approximately 2x the standard monthly Copilot Pro quota (~300/month)
- GPT-4.1 (0x cost — would have been free) never ran because Opus exhausted the quota
- GPT-5.4-mini never ran for the same reason

---

## Recovery

Claude proposed alternatives:
- Run remaining models without Copilot (Sonnet on CLI, Gemma via Gemini API, OpenRouter)
- User accepted: "(b) keep the rest running"
- User later added paid OpenRouter key for GPT-5 Mini and GPT-5.4 Mini

Final dataset (as of incident close):
- Sonnet 4.6: 360/360 ✅
- Haiku 4.5: 360/360 ✅
- GPT-5.4 Mini (paid OpenRouter): 360/360 ✅
- Opus 4.6: 204/360 (4 prompts complete, 2 missing) ⚠️
- Opus 4.1 (Claude CLI replacement): in progress
- Gemma 4 31B: in progress
