# Cross-Language Extension Summary

The cross-language extension tests Python and Go prompts using the same condition structure as the main replication.
GPT-5.3 Codex failed the first cross-language cell after three Codex route errors and is excluded from cross-language conclusions.

## Coverage

| Model | Valid | Errors | Vulnerable | Rate |
| --- | ---: | ---: | ---: | ---: |
| `gpt-5.4` | 240/240 | 0 | 62 | 25.8% |
| `gpt-5.4-mini` | 240/240 | 0 | 62 | 25.8% |
| `gpt-5.3-codex` | 0/240 | 3 | 0 | n/a |
| `claude-opus-4.6` | 240/240 | 0 | 144 | 60.0% |
| `claude-sonnet-4.6` | 240/240 | 0 | 195 | 81.2% |
| `claude-haiku-4.5` | 240/240 | 0 | 160 | 66.7% |

## Aggregate By Condition, Completed Models Only

| Condition | Vulnerable | Total | Rate |
| --- | ---: | ---: | ---: |
| control | 355 | 400 | 88.8% |
| negative-framing | 115 | 400 | 28.8% |
| positive-framing | 153 | 400 | 38.2% |

## Aggregate By Prompt, Completed Models Only

| Prompt | Vulnerable | Total | Rate |
| --- | ---: | ---: | ---: |
| py-exec-dynamic | 177 | 300 | 59.0% |
| py-md5-hash | 162 | 300 | 54.0% |
| py-insecure-random | 180 | 300 | 60.0% |
| go-exec-cmd | 104 | 300 | 34.7% |

## Interpretation

- Cross-language evidence is directional, not final, because one GPT-family model failed the Codex route.
- Rule injection remains useful in Python dynamic-execution and Go shell-command cells.
- Python MD5 and insecure-random results expose a language-rule limitation: the current rules are still partly JavaScript-oriented, so this extension should be interpreted as a stress test of portability rather than a final language-specific secure-coding benchmark.
- A stronger cross-language paper version should use language-specific negative and positive rule text.

Figure: `figures/fig-pro-cross-language.png`
