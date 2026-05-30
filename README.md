# Rules Work, Polarity Doesn't

**A Multi-Model Replication of Security Rule Framing Effects in LLM Coding Agents**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19509466.svg)](https://doi.org/10.5281/zenodo.19509466)

**Author:** [Adhithya Rajasekaran](https://orcid.org/0009-0004-1682-7958) (adhithya@axonome.xyz)

**Status:** active manuscript. The Zenodo DOI currently points to the pilot version; publish a new Zenodo version only after the 2,160-trial paper is frozen.

## Summary

This repository contains a 2,160-trial empirical replication study on persistent security rules for LLM coding agents. The pilot paper, *Don't Say Never*, suggested that prohibition-framed rules could backfire in a specific model/prompt cell. The larger replication does not support that as a general rule.

The robust finding is simpler:

> Targeted security rules reduce vulnerable code generation across all six tested coding agents. The polarity of the rule, prohibition vs safe-alternative framing, is not a reliable general-purpose safety lever.

The repository also includes a completed **1,080-trial non-API-naming extension**. It shows that removing explicit insecure API names does not make all prompts safe: formula-evaluation tasks remain vulnerable without naming `eval()`, while hash and token prompts are 0/720 vulnerable without naming MD5 or `Math.random()`.

## Final Dataset

- **Models:** GPT-5.4, GPT-5.4 Mini, GPT-5.3 Codex, Claude Opus 4.6, Claude Sonnet 4.6, Claude Haiku 4.5
- **Provider stacks:** 3 OpenAI Codex/GPT models via Codex CLI, 3 Anthropic Claude models via Claude CLI
- **Prompts:** 6 vulnerability-eliciting prompts
- **CWE classes:** CWE-94, CWE-328, CWE-319, CWE-338
- **Conditions:** control, negative framing, positive framing
- **Trials:** 6 models x 6 prompts x 3 conditions x 20 trials = **2,160 valid trials**
- **Final errors:** 0

## Key Findings

| Finding | Evidence |
| --- | --- |
| Rule injection works. | Control vulnerability rates of 48-87% fall to 2-23% when rule conditions are pooled. Fisher's exact p < 0.001 in all 6 models. |
| Polarity does not generalize. | Negative vs positive framing is not significant for any model in aggregate. |
| The pilot backfire does not replicate. | No cell in the final 36-cell replication reproduces the pilot's 50%-vs-20% prohibition backfire. |
| Local heterogeneity remains. | Some prompt/model cells move in opposite directions, so rule wording should be tested against the target agent stack. |
| Non-API risk is prompt-class dependent. | Formula evaluation remains high-risk without naming `eval()` (85/120 control vulnerable), while hash/token prompts are 0/720 vulnerable. |

## Validation Status

The 2,160-trial files preserve code previews, not full generated outputs. Bounded GPT-family and Claude-family full-output validation reruns found two detector risks in the original regex labeling: prose-only refusals quoting unsafe `http://` URLs can false-positive, and JavaScript `Function(...)` constructors can false-negative for CWE-94. The runner is patched for future runs, and the validation artifacts are tracked under `experiments/validation/`.

Current validation slice:

- 60 manually labeled full-output reruns.
- 30 GPT-family rows and 30 Claude-family rows.
- Recorded detector labels on labeled reruns: 5 FP, 3 FN.
- Patched detector on labeled reruns: 0 FP, 0 FN.
- OpenRouter Claude validation cost: about `$0.1896`.

Current paper status: strong replication with a 60-row full-output detector-validation slice and a completed 1,080-trial non-API extension using the patched detector. Before archival submission, the remaining empirical upgrade is a four-arm decomposition if the venue requires cleaner causal isolation of polarity from information content.

## Main Artifacts

| Artifact | Path |
| --- | --- |
| Main LaTeX draft | `paper/arxiv/paper.tex` |
| Current PDF draft | `paper/arxiv/paper.pdf` |
| Standalone abstract | `paper/arxiv/abstract.txt` |
| Final replication data | `experiments/data/pro-replication/main/` |
| Non-API extension data | `experiments/data/pro-replication/non-api/` |
| Final runner | `experiments/scripts/pro-six-model-replication.py` |
| Non-API analysis | `experiments/analysis/non-api-extension-summary.md` |
| Detector validation artifacts | `experiments/validation/` |
| Combined validation summary | `experiments/validation/detector-validation-combined-summary.md` |
| Aggregate figure | `figures/fig-pro-gpt-vs-claude-bars.png` |
| Polarity heatmap | `figures/fig-pro-polarity-heatmap.png` |
| Control baseline heatmap | `figures/fig-pro-control-baseline-heatmap.png` |
| Non-API figure | `figures/fig-pro-non-api-control.png` |
| Incident evidence archive | `incidents/2026-04-15-copilot-quota/` |

## Reproducing Figures

Use Python 3.11 on this machine; the system `python3` may not have matplotlib installed.

```bash
python3.11 figures/generate-pro-replication-figures.py
```

The script reads `experiments/data/pro-replication/main/` and regenerates the final figures.

## Submission Direction

The strongest path is no longer a poster submission. Treat this as a full empirical paper.

1. **AISec @ CCS 2026**: best near-term conference/workshop target. The paper fits AI + security and replication/benchmark-style contributions.
2. **TMLR**: possible journal-style target if the paper is framed as an empirical study of instruction-following behavior in learning systems. Requires anonymization and TMLR formatting.
3. **Journal of Information Security and Applications (JISA)**: best conventional journal fit if expanded as applied secure-code-generation guidance with stronger reproducibility and practitioner framing.

## Current Readiness

Ready for a submission polish pass, not yet camera-ready.

Required before submission:

- Resolve venue choice.
- Decide whether the bidirectional instruction-decay incident is a main contribution or an appendix/second paper.
- If strengthening further, run the four-arm decomposition with the patched detector to isolate polarity from information content.
- Verify every cited work exists and is accurately described.
- Fix LaTeX overfull table/reference warnings before submission.
- Freeze repository artifacts and publish Zenodo v2.

## Origin

This research emerged from CodeCoach experiments in which scanner findings were converted into persistent coding-agent rules. A narrow pilot case suggested a prohibition-framing backfire. This repository contains the larger replication showing that rule presence, not polarity, is the robust security effect.

## License

Data and code: MIT. Paper drafts: CC BY 4.0 unless a target venue requires different terms.
