# Experiments: Cross-Agent Security Knowledge Transfer

Research experiments supporting the paper "Scan, Learn, Prevent" and AGNTCon 2026 talk submission.

## Quick Start

```bash
# All experiments run with bun from the backend/ directory
cd backend

# 1. Rule generator validation (no API keys needed)
bun run experiments/rule-generator-eval.ts

# 2. Cross-agent evaluation pipeline (no API keys needed)
bun run experiments/cross-agent-eval.ts

# 3. Real-world repo scanning (needs internet for git clone + registry queries)
bun run experiments/scan-repos.ts

# 4. Automated agent experiment (needs ONE of these API keys)
ANTHROPIC_API_KEY=sk-... bun run experiments/agent-experiment.ts
# or
GEMINI_API_KEY=... bun run experiments/agent-experiment.ts
# or
OPENROUTER_API_KEY=... bun run experiments/agent-experiment.ts
# or install Ollama locally (uses llama3.1:8b as fallback)
```

## Experiments

| Script | What it does | API keys needed |
|--------|-------------|----------------|
| rule-generator-eval.ts | Validates rule generator: coverage, grouping, severity filtering, idempotency | None |
| cross-agent-eval.ts | Generates instruction files + test prompts for manual agent testing | None |
| scan-repos.ts | Clones 8 open-source repos, runs stale AI + ghost dep scanners, generates rules | None (internet needed) |
| agent-experiment.ts | Automated: generates code with/without rules using LLM API, detects vulns | Yes |

## Results (April 5, 2026)

- 7 repos scanned: express, fastify, hono, next-learn, cal.com, twenty, documenso
- 994 total findings (577 stale AI patterns + 417 ghost deps)
- 134 rules generated (87% compression)
- Ghost dependencies found in 7/7 repos
- 5 CWE classes: CWE-1104, CWE-94, CWE-319, CWE-328, CWE-338

## Output Files

```
output/
  paper-draft.md                  # Full academic paper
  provisional-patent-draft.md     # 20-claim patent application
  agntcon-slides-outline.md       # 16-slide deck with timing
  repo-scan-results.json          # Structured scan data
  test-prompts.md                 # 63-trial evaluation protocol
  CLAUDE.md / .cursorrules        # Generated instruction files
  repos/                          # Per-repo instruction files
```
