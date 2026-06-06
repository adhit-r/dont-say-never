# Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing

**A Multi-Model Replication in LLM Coding Agents**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20574220.svg)](https://doi.org/10.5281/zenodo.20574220)

**Author:** [Adhithya Rajasekaran](https://orcid.org/0009-0004-1682-7958) (adhithya@axonome.xyz)

**Status:** Zenodo v2 published at https://doi.org/10.5281/zenodo.20574220. The earlier pilot remains available at https://doi.org/10.5281/zenodo.19509466.

## Summary

This repository contains a 2,160-trial empirical replication study on persistent security rules for LLM coding agents. The pilot paper, *Don't Say Never*, suggested that prohibition-framed rules could backfire in a specific model/prompt cell. The larger replication does not support that as a general rule.

The robust finding is simpler:

> Targeted security rules reduce detector-counted insecure API use across all six tested coding agents. Positive framing has no consistent aggregate advantage over prohibition framing in this benchmark.

The repository also includes a completed **1,080-trial non-API-naming extension**, a **2,160-valid-row four-arm decomposition with 5 retained failed attempts disclosed**, a bounded **1,200-row cross-language extension** across five completed models, and a partial **480-row GPT-family control-baseline extension**. The non-API extension shows that removing explicit insecure API names does not make all prompts safe: formula-evaluation tasks remain vulnerable without naming `eval()`, while hash and token prompts are 0/720 vulnerable without naming MD5 or `Math.random()`. The four-arm decomposition separates pure prohibition, pure alternative guidance, and combined guidance. The cross-language extension is directional evidence for Python/Go portability, with GPT-5.3 Codex excluded due to route errors and language-specific rule text still needed. The control-baseline extension tests whether the original control was too adversarial by adding neutral and generic secure-coding controls; GPT-5.4 and GPT-5.4 Mini are complete for this checkpoint, GPT-5.3 Codex is route-blocked, and Claude-family neutral/generic controls remain pending.

## Final Dataset

- **Models:** GPT-5.4, GPT-5.4 Mini, GPT-5.3 Codex, Claude Opus 4.6, Claude Sonnet 4.6, Claude Haiku 4.5
- **Provider stacks:** 3 OpenAI Codex/GPT models via Codex CLI, 3 Anthropic Claude model files from the completed Claude replication; Opus 4.6 has documented mixed-provenance recovery
- **Prompts:** 6 vulnerability-eliciting prompts
- **CWE classes:** CWE-94, CWE-328, CWE-319, CWE-338
- **Conditions:** control, negative framing, positive framing
- **Trials:** 6 models x 6 prompts x 3 conditions x 20 trials = **2,160 valid orchestration rows**
- **Final errors:** 0

## Key Findings

| Finding | Evidence |
| --- | --- |
| Rule injection works. | Control vulnerability rates of 48-87% fall to 2-23% when rule conditions are pooled. Fisher's exact p < 0.001 in all 6 models. |
| Positive framing has no consistent aggregate advantage. | Negative vs positive framing is not significant for any model in aggregate; the statistics companion estimates a positive-minus-negative random-effects risk difference of +1.2 percentage points (90% CI -1.5 to +3.9), inside a +/-5 percentage-point practical-equivalence margin. |
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
- Structural detector audit on the same 60 rows: 20 TP, 40 TN, 0 FP, 0 FN.
- OpenRouter Claude validation cost: about `$0.1896`.

Current paper status: bounded replication with a 60-row full-output detector and functional-validation slice, a completed 1,080-trial non-API extension, a 2,160-valid-row four-arm decomposition with retained failed attempts disclosed, a bounded 1,200-row cross-language extension, and a partial 480-row GPT-family control-baseline checkpoint.

## Main Artifacts

| Artifact | Path |
| --- | --- |
| Main LaTeX draft | `paper/arxiv/paper.tex` |
| Current PDF draft | `paper/arxiv/paper.pdf` |
| Standalone abstract | `paper/arxiv/abstract.txt` |
| Final replication data | `experiments/data/pro-replication/main/` |
| Non-API extension data | `experiments/data/pro-replication/non-api/` |
| Four-arm add-on data | `experiments/data/pro-replication/four-arm-addons/` |
| Cross-language extension data | `experiments/data/pro-replication/cross-language/` |
| Control-baseline extension data (partial) | `experiments/data/pro-replication/control-baselines/` |
| Final runner | `experiments/scripts/pro-six-model-replication.py` |
| Non-API analysis | `experiments/analysis/non-api-extension-summary.md` |
| Four-arm analysis | `experiments/analysis/four-arm-extension-summary.md` |
| Cross-language analysis | `experiments/analysis/cross-language-extension-summary.md` |
| Control-baseline analysis | `experiments/analysis/control-baselines-summary.md` |
| Control-baseline plan | `experiments/CONTROL_BASELINE_EXTENSION_PLAN.md` |
| Statistics companion | `experiments/analysis/hierarchical-framing-stats.md` |
| Statistics JSON export | `experiments/analysis/hierarchical-framing-stats.json` |
| Polarity equivalence strata | `experiments/analysis/polarity-equivalence-strata.csv` |
| Detector validation artifacts | `experiments/validation/` |
| Combined validation summary | `experiments/validation/detector-validation-combined-summary.md` |
| Semantic detector audit | `experiments/validation/semantic-detector-audit.md` |
| Functional/refusal validation | `experiments/validation/functional-refusal/functional-refusal-summary.md` |
| Functional labeling guide | `experiments/validation/functional-refusal/FUNCTIONAL_LABELING_GUIDE.md` |
| Artifact freeze checklist | `ARTIFACT_FREEZE_CHECKLIST.md` |
| Artifact README | `ARTIFACT_README.md` |
| Citation metadata | `CITATION.cff` |
| Zenodo metadata draft | `.zenodo.json` |
| Python dependencies | `requirements.txt` |
| Aggregate figure | `figures/fig-pro-gpt-vs-claude-bars.png` |
| Polarity heatmap | `figures/fig-pro-polarity-heatmap.png` |
| Control baseline heatmap | `figures/fig-pro-control-baseline-heatmap.png` |
| Non-API figure | `figures/fig-pro-non-api-control.png` |
| Four-arm decomposition figure | `figures/fig-four-arm-decomposition.png` |
| Four-arm model heatmap | `figures/fig-four-arm-model-heatmap.png` |
| Rule-design takeaway figure | `figures/fig-rule-design-takeaway.png` |
| Evidence-stack infographic | `figures/fig-evidence-stack-infographic.png` |
| Cross-language figure | `figures/fig-pro-cross-language.png` |
| Control-baseline figure | `figures/fig-control-baselines.png` |
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

Promising empirical paper, but not yet submission-ready for a rigorous venue. A reviewer-style audit on 2026-06-02 identified several blockers that should be resolved before TMLR/AISec/JISA submission.

Required before submission:

- Resolve venue choice.
- Adopt the title "Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing" unless equivalence testing is added.
- Complete neutral and generic-security controls, or clearly label the current control as an adversarial fast-prototyping baseline.
- Keep full-study claims bounded to detector-counted insecure API use under code previews; only the 60-row full-output slice has manual task-satisfaction labels.
- Expand functional task-satisfaction labels beyond the current 60-row slice if making full-dataset functional-correctness claims.
- Keep equivalence claims bounded to the current random-effects sensitivity analysis: aggregate positive-vs-prohibition practical equivalence within +/-5 percentage points, with local heterogeneity.
- Demote the bidirectional instruction-decay incident to an appendix note or separate paper; do not frame it as a main contribution.
- Verify every cited work exists and is accurately described.
- Fix LaTeX overfull table/reference warnings before submission.
- Zenodo v2 published at `10.5281/zenodo.20574220`; next venue-specific work should use this DOI unless submitting anonymously.

## Origin

This research emerged from CodeCoach experiments in which scanner findings were converted into persistent coding-agent rules. A narrow pilot case suggested a prohibition-framing backfire. This repository contains the larger replication showing that targeted rule presence, not positive-vs-negative polarity, is the robust detector-counted effect in this benchmark.

## License

Data and code: MIT. Paper drafts: CC BY 4.0 unless a target venue requires different terms.
