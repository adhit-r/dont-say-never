# Pro Six-Model Replication Runbook

This runbook covers the GPT-vs-Claude expansion for the framing paper.

## Model Set

Final smoke-tested set:

| Provider stack | Model ID | Route |
| --- | --- | --- |
| OpenAI Codex | `gpt-5.4` | `codex exec --model gpt-5.4` |
| OpenAI Codex | `gpt-5.4-mini` | `codex exec --model gpt-5.4-mini` |
| OpenAI Codex | `gpt-5.3-codex` | `codex exec --model gpt-5.3-codex` |
| Anthropic Claude Code | `claude-opus-4.6` | `claude -p --model claude-opus-4-6` |
| Anthropic Claude Code | `claude-sonnet-4.6` | `claude -p --model sonnet` |
| Anthropic Claude Code | `claude-haiku-4.5` | `claude -p --model claude-haiku-4-5-20251001` |

`gpt-5.5` was requested, but did not complete smoke testing through the local Codex CLI. The local Codex model cache listed `gpt-5.4`, `gpt-5.4-mini`, `gpt-5.3-codex`, `gpt-5.3-codex-spark`, and `gpt-5.2`; `gpt-5.4-mini` is used as the nearest available GPT-family substitute.

## Safety Rules

- Do not use Copilot SDK.
- Do not use OpenRouter paid routes.
- Do not reroute a model after errors without recording the route change.
- Run smoke tests outside the filesystem sandbox because Claude and Codex need access to normal auth files.
- Run real trials in small batches and inspect `experiments/data/pro-replication/quota-ledger.jsonl`.
- Failed retry attempts are quota-relevant and are logged in the ledger.
- Error rows do not count toward the 20 valid trials required per cell.
- Default real-run invocation is intentionally conservative: one cell, 30 max attempts, 3 max errors per cell, and $3 metered Claude cost.
- The runner refuses `run` for any selected model whose latest smoke result is not accepted. If Claude smoke reports `Please run /login`, refresh Claude Code authentication before retrying.

## Commands

Smoke test:

```bash
CODEX_TIMEOUT_SEC=120 CLAUDE_TIMEOUT_SEC=120 python3 experiments/scripts/pro-six-model-replication.py smoke
```

If Claude smoke fails with `Invalid authentication credentials`, run `/login` in Claude Code or refresh the Claude CLI subscription token before any Claude trials.

Run one round-robin batch for the main replication:

```bash
CODEX_TIMEOUT_SEC=180 CLAUDE_TIMEOUT_SEC=180 python3 experiments/scripts/pro-six-model-replication.py run --suite main --cells-per-run 1 --max-attempts 30 --max-cost-usd 3 --max-errors-per-cell 3
```

Run strengthening suites:

```bash
python3 experiments/scripts/pro-six-model-replication.py run --suite four-arm --cells-per-run 1 --max-attempts 30 --max-cost-usd 3 --max-errors-per-cell 3
python3 experiments/scripts/pro-six-model-replication.py run --suite non-api --cells-per-run 1 --max-attempts 30 --max-cost-usd 3 --max-errors-per-cell 3
python3 experiments/scripts/pro-six-model-replication.py run --suite cross-language --cells-per-run 1 --max-attempts 30 --max-cost-usd 3 --max-errors-per-cell 3
```

Print progress:

```bash
python3 experiments/scripts/pro-six-model-replication.py summary
```

Generate figures:

```bash
MPLCONFIGDIR=/private/tmp/mpl python3.11 figures/generate-pro-replication-figures.py
```

## Outputs

- Data: `experiments/data/pro-replication/<suite>/<model>.json`
- Smoke tests: `experiments/data/pro-replication/smoke-tests.json`
- Quota ledger: `experiments/data/pro-replication/quota-ledger.jsonl`
- Figures:
  - `figures/fig-pro-gpt-vs-claude-bars.png`
  - `figures/fig-pro-polarity-heatmap.png`
  - `figures/fig-pro-four-arm-decomposition.png`
  - `figures/fig-pro-non-api-control.png`
  - `figures/fig-pro-cross-language.png`

## Imported Claude Main Results

The main-suite Claude files are imported from the completed Phase 2 replication:

- `experiments/data/replication/claude-opus-4.6.json`
- `experiments/data/replication/claude-sonnet-4.6.json`
- `experiments/data/replication/claude-haiku-4.5.json`

They are copied into `experiments/data/pro-replication/main/` with provenance metadata so Claude quota does not need to be spent again. Treat them as reused prior data, not newly collected pro-runner data. The prompt set, conditions, trial count, and detectors match the main pro-replication design; the access pathway/provenance should be disclosed separately from newly collected Codex CLI results.
