# Control-Baseline Extension Summary

This extension addresses the reviewer critique that the original main-suite control was not neutral.

Status note: this is a partial checkpoint. Neutral and generic secure-coding controls are complete only for the GPT-5.4 and GPT-5.4 Mini slice. GPT-5.3 Codex hit route errors for those controls, and Claude-family neutral/generic controls remain pending.

Compared conditions:

- `fast-prototype-control`: reused original main-suite control, which says not to add extra validation/security unless asked.
- `neutral-control`: new control, helpful coding assistant with no security discouragement.
- `generic-security-control`: new control, broad secure-coding instruction but no CWE-specific rule.
- `targeted-combined-rule`: reused four-arm `combined` condition with a concrete CWE-specific prohibition and safe replacement.

## Coverage By Model

| Model | Fast prototype | Neutral | Generic secure | Targeted CWE rule | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gpt-5.4` | 66/120 | 74/120 | 60/120 | 1/120 | 0 |
| `gpt-5.4-mini` | 82/120 | 80/120 | 39/120 | 6/120 | 0 |
| `gpt-5.3-codex` | 81/120 | 0/0 | 0/0 | 4/120 | 3 |
| `claude-opus-4.6` | 58/120 | 0/0 | 0/0 | 1/120 | 0 |
| `claude-sonnet-4.6` | 54/120 | 0/0 | 0/0 | 10/120 | 0 |
| `claude-haiku-4.5` | 104/120 | 0/0 | 0/0 | 21/120 | 0 |

## Aggregate Over Observed Rows

| Stack | Condition | Vulnerable | Total | Rate |
| --- | --- | ---: | ---: | ---: |
| Full model set | fast-prototype-control | 445 | 720 | 61.8% |
| Completed GPT slice only | neutral-control | 154 | 240 | 64.2% |
| Completed GPT slice only | generic-security-control | 99 | 240 | 41.2% |
| Full model set | targeted-combined-rule | 43 | 720 | 6.0% |
| GPT family | fast-prototype-control | 229 | 360 | 63.6% |
| GPT family | neutral-control | 154 | 240 | 64.2% |
| GPT family | generic-security-control | 99 | 240 | 41.2% |
| GPT family | targeted-combined-rule | 11 | 360 | 3.1% |
| Claude family | fast-prototype-control | 216 | 360 | 60.0% |
| Claude family | neutral-control | 0 | 0 | pending |
| Claude family | generic-security-control | 0 | 0 | pending |
| Claude family | targeted-combined-rule | 32 | 360 | 8.9% |

## Interpretation Template

Use this extension to separate three effects:

1. Whether the original control inflated vulnerability by discouraging security.
2. Whether generic secure-coding advice helps without CWE-specific rules.
3. Whether targeted CWE-specific persistent rules outperform generic security advice.

Figure: `figures/fig-control-baselines.png`
