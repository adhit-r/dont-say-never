# Mitigation and Recovery Plan

## Immediate response (within minutes of detection)

1. ✅ **Killed the Copilot batch process** (`pkill -f "comprehensive-replication.py copilot"`)
2. ✅ **Acknowledged the mistake to user** (no deflection, full responsibility)
3. ✅ **Quantified the damage**: 204 trials × 3x = 612 premium requests
4. ✅ **Removed Opus from Copilot SDK config** (script now uses Claude CLI for Opus 4.1)

## Data preservation

- ✅ **Kept the 204 Opus 4.6 trials** in `experiments/data/replication/claude-opus-4.6.json` — usable for paper
- ✅ **Preserved partial-but-clean data** for 4 of 6 prompts

## Workarounds put in place

1. **Opus 4.6 → partial dataset** (4 prompts complete)
2. **Added Opus 4.1 via Claude CLI** as substitute (free under Max sub, no tool loops with `--disallowedTools` flag)
3. **Added GPT-5.4 Mini via paid OpenRouter** (~$2.50 total cost) to replace lost GPT-5 family coverage from Copilot
4. **Dropped OpenRouter free models** as a separate decision (they were 100% erroring anyway)

## Paper impact

The paper will need a clear note in Section 3 (Methodology) and Section 6 (Limitations):

> "Claude Opus 4.6 results cover 4 of 6 prompts (n=204 trials) due to a runtime quota incident during data collection. The pattern across the 4 prompts is highly consistent (Opus 4.6 produces vulnerable code only on md5-hash, all other prompts 0/20 baseline), suggesting the missing 2 prompts would not change the overall conclusion. We additionally include Claude Opus 4.1 (n=360) collected via a different access pathway."

## Lessons for future Claude Code sessions

For Anthropic / Claude Code maintainers:

1. **Cost tracking should persist across plan revisions.** When Claude makes script edits that affect cost (here: moving a model to a higher-multiplier API), it should re-run cost math against any previously stated budget constraints.

2. **Confirmation before high-cost actions.** When a single edit changes projected cost by >25% of stated budget, Claude should pause and confirm with the user before executing.

3. **Premium quotas should be treated like destructive actions.** The current Claude Code system message prioritizes confirmation for "destructive operations" (rm -rf, force push). API quota consumption that exceeds stated budget should be in the same category.

4. **Cross-context memory.** The user said "save premium for next time" 30+ messages before the mistake. Claude needs to keep budget constraints active across long sessions.

## What user can do

1. **GitHub Copilot Support** (https://support.github.com): Request quota credit for AI-assistant-induced overuse. Cite this incident report.

2. **Anthropic Support** (https://support.anthropic.com): File feedback on Claude Code planning failure. Cite this incident report.

3. **Wait for quota reset** — typically the 1st of the month for GitHub Copilot Pro.
