# Strengthening Roadmap

Current date: 2026-06-06

Current reviewer-safe title:

**Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing**

## Goal

Upgrade the current 2,160-trial paper from a solid empirical replication into a stronger submission package for AISec/TMLR/JISA, and a possible later proper-conference version.

The paper is already credible as a workshop or journal-style empirical result, but a reviewer-style audit on 2026-06-02 identified several top-tier blockers that must be tracked explicitly. The goal of this roadmap is to fix the predictable reviewer objections:

1. "This is only prompt engineering."
2. "The prompts name the insecure APIs, so the setting is artificial."
3. "Regex detectors may be wrong."
4. "Positive and negative framings differ in information content, not just polarity."
5. "The instruction-decay case study is interesting but distracts from the main paper."
6. "The control condition discourages security, so the rule effect may be an artifact of overriding an anti-security instruction."
7. "The title and abstract imply equivalence or universality without equivalence testing."
8. "The dataset is not fully auditable because the main 2,160 rows preserve previews rather than full outputs."

## Progress Board

Status as of commit `d87b509` plus the current checklist update pass.

| Lane | Status | Progress | Evidence | Remaining blocker |
| --- | --- | ---: | --- | --- |
| Core 2,160-trial replication | Done | 100% | `experiments/data/pro-replication/main/`; 6 models x 360 valid rows, 0 errors | None for Zenodo v2 |
| Paper/PDF artifact | Done | 100% | `paper/arxiv/paper.tex`, `paper/arxiv/paper.pdf`; rebuilt with `tectonic` | Venue template later |
| Figures and infographics | Done | 95% | `figures/fig-pro-*.png`, four-arm figures, evidence-stack infographic | Optional visual polish only |
| Detector validation | Strong bounded slice | 75% | 60 full-output reruns, combined summary, semantic detector audit with 0 patched mismatches | 180/360 blinded sample for stronger conference claim |
| Functional/refusal validation | Bounded slice done | 70% | 60 manually task-labeled rows: 34 secure+functional, 20 vulnerable+functional, 4 secure+nonfunctional, 2 refusal/no-code | Compile/unit checks or larger full-output rerun |
| Four-arm decomposition | Done | 100% | `experiments/data/pro-replication/four-arm-addons/`; combined rules strongest | None for current claim |
| Non-API extension | Done | 100% | `experiments/data/pro-replication/non-api/`; 1,080 valid, 0 errors | Optional larger prompt set |
| Cross-language extension | Partial but useful | 70% | 5 models complete; GPT-5.3 Codex route-error only | Language-specific rules and GPT-5.3 route recovery |
| Neutral/generic control extension | Started | 10% | `gpt-5.4-mini / eval-usage / neutral-control` has 20 rows | Complete neutral + generic controls |
| Statistics | Solid but not final TMLR | 75% | Wilson CIs, odds ratios, FDR, regularized fixed-effect sensitivity | Full Bayesian/hierarchical model or equivalence tests |
| Reproducibility package | Zenodo-ready | 95% | `dist/dont-say-never-zenodo-v2-artifact.zip`; `SHA256SUMS`; metadata files | Publish Zenodo v2 DOI |
| Venue packaging | Not started | 15% | Strategy/checklist exists | ACM/TMLR/JISA template conversion |

Overall readiness:

- Zenodo v2 artifact: **95%**. Remaining step is upload/publish DOI.
- AISec/JISA-style empirical paper: **70%**. Strong enough after Zenodo, stronger if neutral/generic controls are completed.
- TMLR submission: **60%**. Needs anonymization, stronger instruction-following framing, and ideally hierarchical/equivalence analysis.
- Proper full-conference version: **45%**. Needs multi-turn agent workflow and larger blinded/full-output validation.

Next recommended parallel work:

1. **Release lane**: publish Zenodo v2, then update DOI in README/CITATION.
2. **Controls lane**: complete neutral helpful-assistant and generic secure-coding controls.
3. **Stats lane**: add full hierarchical or equivalence testing only if the venue requires it.
4. **Agentic lane**: design multi-turn workflow as a separate extension, not a Zenodo blocker.

## Immediate Corrections From Reviewer Critique

Status as of 2026-06-02:

- The pilot 5/10 vs 2/10 backfire cell was previously over-interpreted. Recomputed Fisher's exact test for the stated table gives two-sided `p approx. 0.350` and one-sided `p approx. 0.175`, not `p=0.016`. The paper must treat this as a descriptive anomaly and motivation only.
- The current control prompt is adversarial because it discourages extra validation/security unless asked. Keep it, but rename it as a fast-prototyping or adversarial baseline and add neutral/generic-security controls before claiming ordinary coding-agent security improvement.
- "Polarity doesn't" is too strong unless supported by equivalence testing. The safer claim is: positive framing shows no consistent aggregate advantage over prohibition framing in this benchmark.
- The instruction-decay/quota incident is useful but should not become a second main claim unless backed by a controlled decay experiment.

## Current Baseline

Final dataset:

- 6 models
- 6 prompts
- 3 conditions
- 20 trials per cell
- 2,160 valid orchestration rows
- 0 final errors

Main result:

- Targeted security rules reduce detector-counted insecure API use across every tested model.
- Positive vs negative polarity does not generalize.

This result is publishable, but the stronger version needs validation and decomposition.

## Submission Strategy

### Primary 2026 Target: AISec @ CCS

Use AISec if the submission site opens and the CFP remains active.

Positioning:

> An empirical security measurement paper on persistent instruction-policy guardrails for LLM coding agents.

Do not position it as a prompt-engineering paper.

Core claim:

> Security rule presence is robust; polarity is not a reliable security lever.

Expected shape:

- 8-10 page ACM workshop paper.
- Main paper focused on the 2,160-trial replication.
- Instruction-decay incident shortened to a methodological note or appendix.
- Artifact release emphasized.

### Secondary 2026 Target: TMLR

Use TMLR if the AISec submission site remains unavailable or if the paper is reframed toward ML behavior.

Positioning:

> A negative result on a plausible instruction-following hypothesis, with a security coding-agent domain.

Required changes:

- Stronger framing around instruction following.
- Less CodeCoach/product language.
- Anonymization.
- Incident either removed or converted into a short appendix unless a controlled decay experiment is added.

### Journal Target: JISA

Use JISA if the goal is a conventional journal submission with applied security emphasis.

Positioning:

> Practical evaluation of persistent security guardrails in AI-assisted secure coding.

Required changes:

- More secure-code-generation related work.
- Detector validation.
- Practitioner guidance.
- Artifact/reproducibility appendix.

### Later Proper Conference Target

For ACSAC 2027 or similar applied-security conferences, add at least one ecological-validity extension:

- non-API prompts;
- multi-turn agent workflows;
- real repository patch tasks;
- manual security review of outputs.

## Work Package A: Submission Hygiene

Priority: mandatory.

Timeline: 1-2 days.

Tasks:

1. Remove stale 2,004-trial/Gemma/Opus-4.1 claims from every public-facing file.
2. Verify all figures in the PDF correspond to the 2,160-trial final dataset.
3. Verify all cited papers exist and are described accurately.
4. Add a clear artifact map:
   - dataset path;
   - runner path;
   - figure-generation path;
   - exact model aliases;
   - detector rules.
5. Create a submission checklist for the chosen venue.

Acceptance criteria:

- README, abstract, paper, and strategy files all describe the same dataset.
- PDF compiles cleanly enough for review.
- No SOUPS-poster path is presented as the main plan.

## Work Package B: Detector Validation

Priority: highest evidence upgrade.

Current status:

- A deterministic validation index has been generated:
  - `experiments/validation/detector-validation-sample.jsonl`
  - `experiments/validation/detector-validation-labels.csv`
  - `experiments/validation/detector-validation-summary.md`
- The existing final 2,160-trial JSON files store only `code_preview`, not full extracted code.
- The runner has been patched so future runs preserve the full extracted `code` field.
- Therefore, true detector validation of the original final dataset is blocked unless sampled cells are rerun or raw outputs are recovered from an external transcript/cache.
- A first GPT-family full-output validation rerun has been completed:
  - `experiments/validation/reruns/detector-validation-rerun-results.jsonl`
  - `experiments/validation/reruns/detector-validation-rerun-labels.csv`
  - `experiments/validation/reruns/detector-validation-rerun-summary.md`
- A first Claude-family full-output validation rerun has been completed through OpenRouter because Claude CLI was unavailable:
  - `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-results.jsonl`
  - `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-labels.csv`
  - `experiments/validation/openrouter-claude-reruns/detector-validation-openrouter-claude-summary.md`
- Combined detector-validation summary:
  - `experiments/validation/detector-validation-combined-summary.md`
- This slice found two concrete detector risks:
  - CWE-319 false positives when a model refused but quoted the unsafe `http://` URL in prose.
  - CWE-94 false negatives when a model used `Function(...)` / `new Function(...)` instead of literal `eval(...)`.
- The runner has been patched for future runs to treat refusal-only prose as no generated code and to count JavaScript `Function` constructors as CWE-94 dynamic execution.
- Combined status: 60 manually labeled full-output reruns; recorded detector labels had 5 false positives and 3 false negatives; patched detector had 0 observed mismatches in this slice.
- Semantic detector audit completed:
  - `experiments/scripts/semantic-detector-audit.py`
  - `experiments/validation/semantic-detector-audit.md`
  - result on the 60-row full-output slice: 20 TP, 40 TN, 0 FP, 0 FN.
  - scope boundary: structural sanity audit over observed failure modes, not full AST/Semgrep coverage over all 2,160 rows.

Reviewer objection addressed:

> "Regex detectors are brittle. How do we know the vulnerability labels are correct?"

Design:

1. Draw a stratified sample from the 2,160 outputs:
   - all six models;
   - all six prompts;
   - all three conditions;
   - include both vulnerable and non-vulnerable detector labels.
2. Manually annotate whether the generated code contains the target vulnerability.
3. Report:
   - detector precision;
   - detector recall estimate where possible;
   - common false-positive/false-negative patterns.

Recommended sample:

- Minimum: 180 outputs.
- Stronger: 360 outputs, one-sixth of the dataset.

Immediate next validation step:

- For Zenodo v2: no blocker; current detector validation is adequate if claims remain bounded to detector-counted insecure API use plus a 60-row full-output validation slice.
- For AISec/JISA: consider expanding the manual slice to 180 rows only if reviewers or target formatting allow.
- For TMLR/proper conference: run a 360-row blinded full-output validation slice with functional labels.
- Do not update the paper's final 2,160-trial numerical claims from validation reruns alone; use validation to justify detector limitations, detector fixes, and the next full-code extension.

Deliverables:

- `experiments/validation/detector-validation-sample.jsonl`
- `experiments/validation/detector-validation-labels.csv`
- `experiments/validation/detector-validation-summary.md`
- `experiments/validation/semantic-detector-audit.md`
- table in paper: detector precision by CWE class.

Paper impact:

This turns the paper from "regex-counted prompt outputs" into a more defensible security measurement study.

## Work Package B2: Full-Output and Functional Correctness Rerun

Priority: critical for a stronger conference or TMLR submission.

Current status:

- Offline classifier added at `experiments/scripts/classify-functional-refusal-validation.py`.
- Generated outputs:
  - `experiments/validation/functional-refusal/functional-refusal-classifications.jsonl`
  - `experiments/validation/functional-refusal/functional-refusal-labels.csv`
  - `experiments/validation/functional-refusal/functional-refusal-summary.md`
- Current 60-row validation slice: 20 manually vulnerable, 40 manually non-vulnerable.
- Manual task-satisfaction labels are complete for the 60-row slice:
  - 34 secure+functional;
  - 20 vulnerable+functional;
  - 4 secure+nonfunctional;
  - 2 refusal/no-code.
- TypeScript compile checks were not run because `tsc` is not installed; functional labels are manual task-satisfaction labels, not compile-proof labels.

Reviewer objection addressed:

> "The main dataset preserves only previews, so outputs cannot be audited, compiled, semantically analyzed, or checked for task satisfaction."

Design:

1. Preserve full raw model output and extracted code for every row.
2. Add output categories:
   - refusal/no-code;
   - secure but non-functional;
   - secure and functional;
   - vulnerable but non-functional;
   - vulnerable and functional.
3. Add per-prompt smoke tests where feasible:
   - TypeScript/JavaScript parsing and minimal unit tests;
   - Python AST parsing and minimal unit tests;
   - Go compile/test checks for Go snippets.
4. Use patched detectors from the start.

Minimum version:

- 360-row stratified full-output rerun with blind manual labels and functional labels.

Strong version:

- full 2,160-row rerun with full outputs, semantic detectors, and functional correctness.

Paper impact:

This separates "model avoided the banned token" from "model produced secure usable code," which is the difference between a prompt-output study and a security measurement paper.

## Work Package B3: Neutral and Generic-Security Controls

Priority: critical for claim validity.

Current status:

- Suite added to `experiments/scripts/pro-six-model-replication.py` as `control-baselines`.
- Plan added at `experiments/CONTROL_BASELINE_EXTENSION_PLAN.md`.
- Summary script added at `experiments/scripts/summarize-control-baselines.py`.
- First checkpoint completed: `gpt-5.4-mini / eval-usage / neutral-control` yielded 8/20 vulnerable outputs with 0 errors.
- Remaining target: 1,420 new rows.

Reviewer objection addressed:

> "Your control says not to add extra validation or security, so the rule effect may be an artifact of overriding an anti-security instruction."

Design:

Add:

1. Neutral helpful coding assistant control.
2. Current fast-prototyping/no-extra-security control, retained as adversarial baseline.
3. Generic secure-code control.

Interpretation:

- Current control vs rules: targeted rules override fast-prototyping pressure.
- Neutral control vs rules: targeted rules improve ordinary coding-agent output.
- Generic secure control vs CWE-specific rules: targeted persistent rules beat broad security advice.

Paper impact:

This is one of the biggest upgrades because it directly protects the core "rules work" claim.

## Work Package C: Four-Arm Decomposition

Priority: high if aiming TMLR or a stronger conference.

Current status: completed.

Reviewer objection addressed:

> "Negative and positive rules differ in information content. You did not isolate polarity."

Design:

Four conditions:

1. Control: no rule.
2. Pure negative: names the forbidden construct only.
3. Pure positive: names only the safe alternative.
4. Combined: names both the forbidden construct and the safe alternative.

Completed design:

- Reuse existing control where possible.
- Added 3 new arms x 6 models x 6 prompts x 20 trials = 2,160 add-on rows.
- Combined with reused control rows from the main suite.

Deliverables:

- `experiments/data/pro-replication/four-arm-addons/`
- `experiments/analysis/four-arm-extension-summary.md`
- `figures/fig-four-arm-decomposition.png`
- paper section: "Polarity vs Information Content"

Paper impact:

This is the single cleanest way to strengthen the causal interpretation. The completed result supports the information-content account: combined rules are strongest, while pure-positive guidance is not uniformly safer than pure-negative guidance.

## Work Package D: Non-API Prompt Replication

Priority: high for security reviewers.

Current status: completed.

- Valid rows: 1,080.
- Models: 6.
- Prompts: 3.
- Conditions: control, negative framing, positive framing.
- Errors: 0.
- Data: `experiments/data/pro-replication/non-api/`.
- Analysis: `experiments/analysis/non-api-extension-summary.md`.
- Figure: `figures/fig-pro-non-api-control.png`.

Main result:

- Formula evaluation remains high-risk without naming `eval()`: control 85/120 vulnerable.
- Rules still help on formula evaluation: pooled rules 76/240 vulnerable, Fisher's exact `p=2.88e-12`, Cohen's `h=0.805`.
- Negative framing is stronger than positive framing for formula evaluation: 21/120 vs 55/120, Fisher's exact `p=3.58e-06`.
- Hash and token prompts are inert without explicit unsafe API names: 0/720 vulnerable across all models and conditions.

Interpretation:

The earlier "double priming is necessary" framing was too broad. API-name priming is unnecessary for dynamic-expression tasks because task semantics alone invite dynamic execution. It appears necessary for MD5 and insecure-random tasks in this prompt set.

Reviewer objection addressed:

> "The prompts explicitly name eval, MD5, HTTP, and Math.random. That overstates priming effects and may not reflect real developer requests."

Design:

Create semantically equivalent tasks that do not name the insecure API.

Examples:

- "Evaluate a user-provided formula string" instead of "use eval."
- "Generate a stable document fingerprint" instead of "use MD5."
- "Call a health endpoint at a configurable URL" instead of writing `http://`.
- "Generate a short reset token" instead of "use Math.random."

Recommended design:

- 6 models x 6 non-API prompts x 3 conditions x 20 trials = 2,160 additional trials.

Budget-reduced design:

- 3 models x 6 prompts x 3 conditions x 20 = 1,080 additional trials.

Deliverables:

- `experiments/data/non-api-replication/`
- `figures/fig-non-api-replication.png`
- paper section: "Ecological Validity: Non-API Prompts"

Paper impact:

If rules still help, the paper becomes much stronger. If rules become inert, that is also valuable: it means rule files mainly help when the user prompt activates a vulnerable pattern.

## Work Package E: Multi-Turn Agent Workflow

Priority: medium for AISec, high for proper conference.

Reviewer objection addressed:

> "Single-turn code generation is not how coding agents are used."

Design:

Use real agent workflows:

1. Agent receives a repository task.
2. It writes or edits code.
3. It may inspect files.
4. It may run tests.
5. Final patch is scanned.

Minimal version:

- 2 models:
  - GPT-5.4 or GPT-5.3 Codex
  - Claude Sonnet 4.6 or Opus 4.6
- 3 CWE tasks
- 3 conditions
- 10 trials per cell
- 180 agentic trials.

Deliverables:

- `experiments/data/agentic-workflow/`
- `experiments/tasks/agentic-cwe-tasks/`
- paper section or appendix: "Agentic Workflow Check"

Paper impact:

This upgrades ecological validity, but it is slower and more expensive than detector validation or four-arm decomposition.

## Work Package F: Cross-Language Extension

Priority: medium.

Reviewer objection addressed:

> "All prompts are TypeScript-like; this may not generalize."

Design:

Add small language subsets:

- Python: dynamic execution, weak hash, insecure random.
- Go: command execution or HTTP transport.
- JavaScript/TypeScript: existing baseline.

Budget-reduced design:

- 3 models x 3 language prompts x 3 conditions x 20 = 540 trials.

Deliverables:

- `experiments/data/cross-language/`
- `figures/fig-cross-language.png`

Paper impact:

Good for generality, but less important than detector validation and non-API replication.

## Work Package G: Instruction-Decay Follow-Up

Priority: separate-paper candidate.

Reviewer objection addressed:

> "The Copilot quota incident is n=1 and distracts from the main empirical paper."

Decision:

Do not let this dominate the AISec/JISA paper.

Best use:

- Move most incident details to appendix.
- Keep one paragraph in the main paper:
  - incident motivated future work on instruction decay;
  - evidence archived;
  - not part of the main causal claim.

If converting to a second paper:

Controlled design:

- instruction stated once;
- insert 0, 2k, 8k, 32k, 64k distractor tokens;
- ask model to perform a cost-sensitive or rule-sensitive action;
- measure compliance.

This could become:

**Instruction Decay in Long-Context Coding Agents**

## Work Package H: Hierarchical and Equivalence Statistics

Priority: high for TMLR; medium-high for AISec/JISA.

Current status:

- Statistics companion added at `experiments/scripts/hierarchical-framing-stats.py`.
- Generated report: `experiments/analysis/hierarchical-framing-stats.md`.
- Generated machine-readable export: `experiments/analysis/hierarchical-framing-stats.json`.
- Completed: Wilson confidence intervals, headline risk differences, Haldane-corrected odds ratios, Fisher tests, and Benjamini-Hochberg FDR correction for exploratory per-cell tests.
- Completed as sensitivity analysis: regularized fixed-effect logistic models with provider, CWE, treatment interactions, model indicators, and prompt indicators.
- Still open: full Bayesian hierarchical modeling or equivalence testing. Avoid equivalence-style wording unless that work is added.

Reviewer objection addressed:

> "Non-significance is not equivalence, and per-cell Fisher tests are exploratory without multiple-testing correction."

Tasks:

1. Add aggregate confidence intervals and effect sizes for rule vs control and positive vs negative.
2. Add FDR or Bonferroni correction for per-cell tests.
3. Add mixed-effects logistic regression or Bayesian hierarchical modeling:

```text
vulnerable ~ condition + provider + cwe + api_named + language
           + condition:provider + condition:cwe
           + (1 | model) + (1 | prompt)
```

4. If the title keeps a strong polarity claim, add equivalence testing with a pre-specified smallest effect size of interest.

Paper impact:

This moves the paper from cell-count reporting to reviewer-grade statistical inference.

## Recommended Execution Order

### Phase 1: Make Current Paper Defensible

Time: 2-4 days.

1. Finish submission hygiene.
2. Run detector validation.
3. Rebuild PDF and figures.
4. Decide treatment of incident section.

Outcome:

The paper is credible for AISec/JISA even without new model trials.

### Phase 2: Add One High-Value Experiment

Time: 4-7 days.

Choose one:

- Four-arm decomposition if the target is TMLR.
- Non-API replication if the target is AISec/JISA.

Recommendation:

Run **non-API replication first** because it directly addresses security-reviewer ecological validity.

### Phase 3: Add Proper-Conference Strength

Time: 1-2 weeks.

Add:

- multi-turn agent workflow;
- cross-language subset;
- richer threat model;
- manual audit appendix.

Outcome:

The paper becomes plausible for a later applied-security conference, not only a workshop/journal path.

## Concrete Two-Week Plan

### Week 1

Day 1:

- Finalize README and strategy.
- Add submission checklist.
- Verify citations.
- Move incident-heavy material to appendix branch or mark it optional.

Day 2:

- Build detector-validation sample.
- Start manual labels.
- Add detector validation script.

Day 3:

- Finish detector validation.
- Add detector precision table.
- Update methodology and limitations.

Day 4:

- Create non-API prompt set.
- Smoke-test 2 models.

Day 5:

- Run non-API replication on 3-model reduced design.

Day 6:

- Analyze non-API results.
- Generate figure.
- Update paper.

Day 7:

- Produce AISec-style draft and TMLR-style abstract.

### Week 2

Day 8-9:

- Expand non-API to all six models if results are informative and quota allows.

Day 10:

- Run four-arm reduced design if polarity confound remains the top weakness.

Day 11:

- Update stats and figures.

Day 12:

- Write artifact appendix and reproducibility instructions.

Day 13:

- Full paper review pass.
- Remove overclaims.
- Verify every number in text against JSON.

Day 14:

- Freeze version.
- Publish Zenodo v2.
- Prepare submission package.

## Decision Gate

After Phase 1, decide:

| If detector validation is strong | Continue toward AISec/JISA. |
| If detector validation finds many errors | Fix detectors and rerun analysis before any submission. |
| If non-API prompts show rules still help | Stronger security paper. |
| If non-API prompts show no effect | Reframe: rules help only under explicit vulnerable-pattern activation. Still publishable. |
| If four-arm shows combined is best | Claim information content dominates polarity. |
| If pure negative backfires consistently | Restore a narrower "prohibition risk" claim with stronger evidence. |

## Final Recommendation

Do not rush the current draft. The main result is already useful, but the paper becomes much harder to reject if we add:

1. detector validation;
2. non-API prompt replication;
3. either four-arm decomposition or a short multi-turn agent check.

The highest-return path is:

**Detector validation -> Non-API replication -> AISec/JISA-ready paper.**
