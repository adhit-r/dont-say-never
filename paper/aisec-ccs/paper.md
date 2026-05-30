# Rules Work, Polarity Doesn't: A Multi-Model Replication of Security Rule Framing Effects in LLM Coding Agents

**Adhithya Rajasekaran**
Axonome — adhithya@axonome.xyz — ORCID [0009-0004-1682-7958](https://orcid.org/0009-0004-1682-7958)

## Abstract

System-prompt rules are widely used to steer LLM coding agents away from insecure patterns. A popular heuristic, rooted in Wegner's ironic-process theory and reinforced by prompt-engineering folklore, holds that prohibition framing ("NEVER use `eval()`") activates the forbidden behavior, while positive alternatives ("Always use `JSON.parse()`") avoid this rebound. A 645-trial pilot appeared to support this prediction on one model-prompt cell. We report a balanced 6-model replication across 3 OpenAI Codex/GPT models and 3 Anthropic Claude models. Across 6 vulnerability-eliciting prompts, 3 conditions, and 20 trials per cell, we collect 2,160 valid trials with zero final errors. Rule injection reliably reduces vulnerability in every model; control rates of 48-87% fall to 2-23% when the two rule conditions are pooled (Fisher's exact p < 0.001 in all 6 models). Framing polarity does not generalize: negative-vs-positive framing is not significant for any model in aggregate. The pilot's isolated prohibition backfire does not reproduce across the broader 36-cell replication. A 1,080-trial non-API-naming extension shows a more nuanced ecological-validity result: formula-evaluation tasks remain vulnerable without naming `eval()`, while hash and token prompts are inert without naming MD5 or `Math.random()`.

## 1 Introduction

AI coding agents such as Claude Code, Codex, Cursor, GitHub Copilot, and Goose execute multi-step tasks guided by persistent instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`). These files are now a practical policy layer for steering models away from recurring insecure patterns.

The question is how those rules should be written. Wegner's ironic-process theory suggests that telling humans not to think about a concept can increase its accessibility. A direct LLM analogy predicts that "NEVER use `eval()`" may keep `eval()` active as a monitoring target and increase the chance it appears in generated code. Our earlier pilot found one striking cell consistent with that hypothesis: a prohibition rule produced vulnerable code in 5/10 trials versus 2/10 in control.

This paper tests whether that finding survives a larger replication. It does not. The reliable effect is rule presence, not polarity.

## 2 Method

We run a 6 model × 6 prompt × 3 condition × 20 trial design: 2,160 valid trials.

Models:

| Model | Provider stack | Access pathway | Trials |
|---|---|---:|---:|
| GPT-5.4 | OpenAI Codex/GPT | Codex CLI | 360 |
| GPT-5.4 Mini | OpenAI Codex/GPT | Codex CLI | 360 |
| GPT-5.3 Codex | OpenAI Codex/GPT | Codex CLI | 360 |
| Claude Opus 4.6 | Anthropic Claude | Claude CLI | 360 |
| Claude Sonnet 4.6 | Anthropic Claude | Claude CLI | 360 |
| Claude Haiku 4.5 | Anthropic Claude | Claude CLI | 360 |

Conditions:

| Condition | Description |
|---|---|
| Control | Base coding prompt only |
| Negative framing | Rule prohibits insecure API or pattern |
| Positive framing | Rule suggests a safe alternative pattern |

Prompts target CWE-94 (`eval()`), CWE-328 (MD5), CWE-319 (`http://`), and CWE-338 (`Math.random()`).

GPT models use `codex exec` with rules injected through a real `AGENTS.md` in an ephemeral read-only workdir. Claude models use `claude -p --append-system-prompt` with tools disabled. Generated code is classified by CWE-specific detectors over comment-stripped source.

## 3 Results

### 3.1 Rule Injection Works

| Model | Control | Negative | Positive | Any rule | Fisher p, control vs any rule |
|---|---:|---:|---:|---:|---:|
| GPT-5.4 | 66/120 | 18/120 | 24/120 | 42/240 | 8.41e-13 |
| GPT-5.4 Mini | 82/120 | 27/120 | 27/120 | 54/240 | 4.10e-17 |
| GPT-5.3 Codex | 81/120 | 15/120 | 12/120 | 27/240 | 1.52e-27 |
| Claude Opus 4.6 | 58/120 | 0/120 | 4/120 | 4/240 | 3.35e-28 |
| Claude Sonnet 4.6 | 54/120 | 18/120 | 30/120 | 48/240 | 1.77e-06 |
| Claude Haiku 4.5 | 104/120 | 31/120 | 24/120 | 55/240 | 3.26e-32 |

All six models show a strong reduction when a security rule is present.

### 3.2 Polarity Does Not Generalize

| Model | Negative | Positive | Fisher p | Direction |
|---|---:|---:|---:|---|
| GPT-5.4 | 18/120 | 24/120 | 0.396 | Positive worse, ns |
| GPT-5.4 Mini | 27/120 | 27/120 | 1.000 | Equal |
| GPT-5.3 Codex | 15/120 | 12/120 | 0.684 | Positive better, ns |
| Claude Opus 4.6 | 0/120 | 4/120 | 0.122 | Positive worse, ns |
| Claude Sonnet 4.6 | 18/120 | 30/120 | 0.075 | Positive worse trend, ns |
| Claude Haiku 4.5 | 31/120 | 24/120 | 0.357 | Positive better, ns |

No model shows a statistically significant aggregate advantage for positive framing.

### 3.3 Per-Prompt Detail

Values are vulnerable trials as Control / Negative / Positive.

| Prompt | GPT-5.4 | GPT-5.4 Mini | GPT-5.3 Codex | Opus 4.6 | Sonnet 4.6 | Haiku 4.5 |
|---|---:|---:|---:|---:|---:|---:|
| eval-usage | 0 / 0 / 0 | 0 / 0 / 0 | 2 / 0 / 0 | 0 / 0 / 0 | 9 / 0 / 6 | 13 / 0 / 1 |
| md5-hash | 20 / 2 / 10 | 19 / 8 / 14 | 12 / 4 / 1 | 15 / 0 / 0 | 1 / 1 / 1 | 20 / 0 / 0 |
| http-url | 19 / 15 / 13 | 19 / 13 / 12 | 18 / 7 / 11 | 0 / 0 / 4 | 0 / 1 / 1 | 17 / 15 / 7 |
| insecure-random | 5 / 0 / 0 | 20 / 0 / 0 | 17 / 0 / 0 | 14 / 0 / 0 | 20 / 0 / 0 | 20 / 0 / 0 |
| eval-dynamic | 2 / 1 / 1 | 4 / 6 / 1 | 12 / 4 / 0 | 9 / 0 / 0 | 4 / 0 / 2 | 16 / 16 / 15 |
| weak-hash | 20 / 0 / 0 | 20 / 0 / 0 | 20 / 0 / 0 | 20 / 0 / 0 | 20 / 16 / 20 | 18 / 0 / 1 |

### 3.4 Non-API-Naming Extension

We also ran a 1,080-trial extension that removes explicit insecure API names from the user prompt while keeping the same six models, three conditions, and 20 trials per cell. The result is prompt-class dependent.

| Prompt | Control | Negative | Positive |
|---|---:|---:|---:|
| Formula evaluator, no API name | 85/120 | 21/120 | 55/120 |
| Fingerprint hash, no API name | 0/120 | 0/120 | 0/120 |
| Signing token, no API name | 0/120 | 0/120 | 0/120 |

Formula evaluation remains high-risk without naming `eval()` because the task semantics invite dynamic execution. Rule injection still helps: pooled rule vulnerability falls from 85/120 to 76/240 (Fisher p = 2.88e-12). Negative framing is stronger than positive framing in this extension: 21/120 vs 55/120 (Fisher p = 3.58e-06). Hash and token prompts are 0/720 vulnerable without explicit API-name priming.

## 4 Discussion

The pilot's Wegner-motivated prediction does not replicate. A prohibition rule is not generally more dangerous than a positive alternative. The more robust pattern is simpler: if a relevant security rule exists, models are less likely to generate vulnerable code.

The result is not a claim that phrasing never matters. Polarity effects occur locally. Claude Sonnet trends worse under positive framing; Claude Haiku trends better; GPT-5.4 Mini is exactly tied in aggregate. These effects are model- and prompt-specific, not a portable rule-writing heuristic.

The strongest practitioner takeaway is therefore: add targeted rules for the relevant CWE classes, but measure phrasing against the actual model stack. Do not rely on the general advice that "never" should always be avoided.

## 5 Limitations

The main prompts explicitly name insecure APIs, so they represent adversarial or high-pressure coding requests rather than ordinary development traffic. The non-API extension partially addresses this: formula evaluation remains high-risk without API names, while hash and token tasks become inert. Detection is regex-based, although applied consistently across conditions and after comment stripping. The experiment is single-turn, while real coding agents often work across multi-turn edit-test loops. The final model set is limited to the tested Codex/GPT and Claude CLI models; GPT-5.5 was requested but did not pass local smoke testing.

## 6 Conclusion

A 2,160-trial, 6-model replication plus a 1,080-trial non-API extension finds that security rules work, but polarity does not generalize. The paper supersedes the pilot's stronger "Don't Say Never" interpretation: prohibition-framed rules can fail locally, but the aggregate evidence does not support avoiding prohibition framing as a general LLM coding-agent security principle.

## AI Tool Disclosure

Claude Code (Anthropic) and Codex were used to assist with experiment script development, data analysis, and manuscript drafting. All experimental design decisions, data interpretation, and scientific conclusions were reviewed and approved by the author.
