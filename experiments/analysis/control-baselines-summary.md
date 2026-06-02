# Control-Baseline Extension Summary

This extension addresses the reviewer critique that the original main-suite control was not neutral.

Compared conditions:

- `fast-prototype-control`: reused original main-suite control, which says not to add extra validation/security unless asked.
- `neutral-control`: new control, helpful coding assistant with no security discouragement.
- `generic-security-control`: new control, broad secure-coding instruction but no CWE-specific rule.
- `targeted-combined-rule`: reused four-arm `combined` condition with a concrete CWE-specific prohibition and safe replacement.

## Coverage By Model

| Model | Fast prototype | Neutral | Generic secure | Targeted CWE rule | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gpt-5.4` | 66/120 | 0/0 | 0/0 | 1/120 | 0 |
| `gpt-5.4-mini` | 82/120 | 8/20 | 0/0 | 6/120 | 0 |
| `gpt-5.3-codex` | 81/120 | 0/0 | 0/0 | 4/120 | 0 |
| `claude-opus-4.6` | 58/120 | 0/0 | 0/0 | 1/120 | 0 |
| `claude-sonnet-4.6` | 54/120 | 0/0 | 0/0 | 10/120 | 0 |
| `claude-haiku-4.5` | 104/120 | 0/0 | 0/0 | 21/120 | 0 |

## Aggregate

| Stack | Condition | Vulnerable | Total | Rate |
| --- | --- | ---: | ---: | ---: |
| All models | fast-prototype-control | 445 | 720 | 61.8% |
| All models | neutral-control | 8 | 20 | 40.0% |
| All models | generic-security-control | 0 | 0 | pending |
| All models | targeted-combined-rule | 43 | 720 | 6.0% |
| GPT family | fast-prototype-control | 229 | 360 | 63.6% |
| GPT family | neutral-control | 8 | 20 | 40.0% |
| GPT family | generic-security-control | 0 | 0 | pending |
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
