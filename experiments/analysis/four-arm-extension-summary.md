# Four-Arm Extension Summary

This summary merges the main-suite `control` rows with the `four-arm-addons` rows.
All GPT-family and Claude-family add-on rows are complete.

## Coverage

| Model | Control | Pure negative | Pure positive | Combined | Add-on errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gpt-5.4` | 66/120 | 3/120 | 5/120 | 1/120 | 3 |
| `gpt-5.4-mini` | 82/120 | 8/120 | 21/120 | 6/120 | 1 |
| `gpt-5.3-codex` | 81/120 | 2/120 | 4/120 | 4/120 | 1 |
| `claude-opus-4.6` | 58/120 | 0/120 | 8/120 | 1/120 | 0 |
| `claude-sonnet-4.6` | 54/120 | 27/120 | 32/120 | 10/120 | 0 |
| `claude-haiku-4.5` | 104/120 | 35/120 | 69/120 | 21/120 | 0 |

## Aggregate By Provider Stack

| Stack | Condition | Vulnerable | Total | Rate |
| --- | --- | ---: | ---: | ---: |
| GPT family | control | 229 | 360 | 63.6% |
| GPT family | pure-negative | 13 | 360 | 3.6% |
| GPT family | pure-positive | 30 | 360 | 8.3% |
| GPT family | combined | 11 | 360 | 3.1% |
| Claude family | control | 216 | 360 | 60.0% |
| Claude family | pure-negative | 62 | 360 | 17.2% |
| Claude family | pure-positive | 109 | 360 | 30.3% |
| Claude family | combined | 32 | 360 | 8.9% |

## Interpretation

- GPT add-on data are complete: 1,080 valid add-on rows plus 360 reused control rows.
- Claude add-on data are complete: 1,080 valid add-on rows plus 360 reused control rows.
- Pure-positive is not uniformly safer. The clearest early example is GPT-5.4 Mini on `md5-hash`, where pure-positive produced 14/20 vulnerable outputs while pure-negative and combined were 0/20.
- Combined rules often repair pure-positive omissions, supporting the information-content explanation rather than a simple positive-vs-negative polarity rule.
- Claude Opus is strongest overall but became vulnerable on `eval-dynamic` pure-positive, so even the strongest model is not uniformly protected by positive-only guidance.

Figure: `figures/fig-four-arm-decomposition.png`
