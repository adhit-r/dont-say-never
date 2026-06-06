# Strengthening Roadmap

Current date: 2026-06-07

Current reviewer-safe title:

**Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing**

## Current Verdict

This is now a credible empirical AI-security paper, but it is not yet top-tier-ready.

The core result is strong and useful:

> Concrete, targeted security rules substantially reduce detector-counted insecure API use in this benchmark; positive wording does not consistently outperform prohibition wording; rule information content appears more important than polarity.

The main weakness is not the headline result. The headline result is probably directionally real. The main weakness is measurement validity: the original 2,160-trial dataset preserves code previews rather than full outputs, and the 60-row full-output validation audit found that the original recorded detector labels had 5 false positives and 3 false negatives before patching.

Reviewer-safe positioning:

- Current form: credible preprint / workshop-grade empirical result.
- After full-output rerun + semantic labels + artifact update: credible AISec / empirical AI-security submission.
- For USENIX Security, CCS, NDSS, ICML, NeurIPS, or ACL main: not enough yet without a larger auditable dataset, stronger semantic analysis, and more naturalistic agent workflows.

## Progress Board

| Lane | Status | Progress | Evidence | Remaining blocker |
| --- | --- | ---: | --- | --- |
| Zenodo v2 release | Done | 100% | DOI `10.5281/zenodo.20574220`; tag `v2.0.0` | None |
| Core 2,160-trial replication | Done | 100% | `experiments/data/pro-replication/main/`; 6 models x 360 valid rows, 0 errors | Full-output audit still bounded |
| Paper/PDF artifact | Done | 100% | `paper/arxiv/paper.tex`, `paper/arxiv/paper.pdf` | Venue template later |
| Figures and infographics | Done | 95% | `figures/fig-pro-*.png`, four-arm figures, evidence-stack infographic | Optional visual polish only |
| Four-arm decomposition | Done | 100% | `experiments/data/pro-replication/four-arm-addons/`; combined rules strongest | None for current claim |
| Non-API extension | Done | 100% | `experiments/data/pro-replication/non-api/`; 1,080 valid, 0 errors | Larger prompt set optional |
| Statistics | Strong but not final top-tier | 90% | Wilson CIs, odds ratios, FDR, fixed-effect sensitivity, random-effects equivalence test | Mixed-effects/Bayesian model for TMLR/top venue |
| Detector validation | Bounded slice | 75% | 60 full-output reruns; patched detector 20 TP / 40 TN / 0 FP / 0 FN on slice | 180/360-row full-output validation |
| Functional/refusal validation | Bounded slice | 70% | 60 manually task-labeled rows | Compile/unit checks or larger full-output rerun |
| Cross-language extension | Partial but useful | 70% | 5 models complete; GPT-5.3 Codex route-error only | Language-specific rules and GPT-5.3 recovery |
| Neutral/generic control extension | Partial GPT checkpoint | 33% full / 67% GPT-only | 480 valid rows; GPT-5.4 and GPT-5.4 Mini complete; GPT-5.3 route-blocked | Claude controls and/or route recovery |
| Opus provenance sensitivity | Not done | 0% | Incident archive exists | Exclude-Opus / clean-route sensitivity table |
| Full-output rerun | Not done | 0% | Runner patched for future full code | 360-row or 2,160-row rerun |
| Multi-turn agent workflow | Not started | 0% | Plan exists conceptually | New repo-task benchmark |
| Venue packaging | Not started | 15% | Strategy/checklist exists | TMLR/ACM/JISA conversion |

Overall readiness:

- Zenodo v2 artifact: **100%**.
- AISec/JISA-style empirical paper: **76%**.
- TMLR submission: **65%**.
- Proper full-conference version: **40%**.

## Reviewer-Derived Priority Order

### P0: Measurement Validity

This is the main blocker.

Problem:

- The main 2,160 rows preserve `code_preview`, not full generated outputs.
- The 60-row validation rerun found 8 original recorded-detector errors out of 60 before patching.
- That error rate is tolerable for a bounded workshop claim, but too high for a top-tier security or empirical software-engineering claim unless expanded.

Action:

1. Run a **360-row stratified full-output rerun**:
   - 6 models x 6 prompts;
   - balanced across control, negative, positive;
   - full raw output preserved;
   - extracted code preserved;
   - patched detectors from the start.
2. Add manual security labels:
   - target insecure API present;
   - semantic equivalent present;
   - refusal/no-code;
   - secure but nonfunctional;
   - secure and functional.
3. Add syntax/compile checks where feasible:
   - TypeScript/JavaScript parsing;
   - Python AST parsing;
   - Go compile/test for Go snippets.

Acceptance criteria:

- `experiments/validation/full-output-360/plan.jsonl`
- `experiments/validation/full-output-360/results.jsonl`
- `experiments/validation/full-output-360/labels.csv`
- `experiments/validation/full-output-360/summary.md`
- paper table: detector precision/recall by CWE and output category.

Claim impact:

> Moves the work from "detector-counted prompt-output study" toward "security measurement study."

### P1: Neutral and Generic Controls

Problem:

The current main control is not neutral. It says not to add extra validation or security unless asked. Reviewers can argue that the headline effect is inflated because targeted rules override an anti-security baseline.

Current status:

- GPT-5.4 and GPT-5.4 Mini are complete for neutral/generic controls.
- GPT-5.3 Codex is route-blocked for this suite.
- Claude neutral/generic controls are pending because Claude CLI subscription access is unavailable.

Action:

1. Complete Claude controls through an approved non-CLI route, or explicitly freeze this as a GPT-family checkpoint.
2. Add a paper table separating:
   - fast-prototyping control;
   - neutral helpful assistant control;
   - generic secure-coding control;
   - targeted CWE-specific combined rule.
3. Do not claim "ordinary coding-agent improvement" until the neutral control is complete enough.

Acceptance criteria:

- `experiments/analysis/control-baselines-summary.md` clearly states denominators and route gaps.
- paper uses "fast-prototyping baseline" instead of "control" where precision matters.

Claim impact:

> Protects the main "rules work" conclusion from the anti-security-control critique.

### P2: Opus 4.6 Mixed-Provenance Sensitivity

Problem:

The Opus 4.6 row has documented mixed provenance from the data-collection incident and recovery. Transparency is good, but a reviewer may ask whether the headline result depends on those rows.

Action:

Add sensitivity analyses:

1. Main results excluding Claude Opus 4.6.
2. Provider-stack aggregates excluding Opus 4.6.
3. If trial-level provenance is recoverable, clean-route-only Opus table.

Acceptance criteria:

- `experiments/analysis/opus-provenance-sensitivity.md`
- one appendix table showing that rule-presence and polarity conclusions do not depend on Opus 4.6.

Claim impact:

> Removes an avoidable route/provenance objection.

### P3: Statistical Model Upgrade

Current statistics are strong enough for the preprint:

- Fisher tests;
- Wilson CIs;
- odds ratios;
- FDR correction;
- regularized fixed-effect sensitivity model;
- random-effects equivalence test over 36 model-prompt strata.

But a TMLR or stronger empirical venue may expect a model that respects the data hierarchy.

Action:

Add a mixed-effects logistic or Bayesian hierarchical model:

```text
vulnerable ~ condition + provider + cwe
           + condition:provider + condition:cwe
           + (1 | model) + (1 | prompt)
```

For polarity:

```text
vulnerable ~ polarity
           + polarity:provider + polarity:cwe
           + (1 | model) + (1 | prompt)
```

Acceptance criteria:

- `experiments/scripts/mixed_effects_framing_model.py` or R script;
- `experiments/analysis/mixed-effects-framing-model.md`;
- paper reports this as primary statistical model or robustness check.

Claim impact:

> Reduces reviewer complaints about pooled Fisher tests and hierarchical dependence.

### P4: Prompt-Set Breadth

Problem:

Six hand-written prompts cannot represent four CWE classes broadly.

Action:

Add variants per CWE:

- CWE-94: `eval`, `Function`, template execution, expression parser misuse.
- CWE-328: MD5, SHA-1, weak checksum used as security fingerprint.
- CWE-319: plaintext API endpoint, credential-bearing HTTP URL, insecure webhook.
- CWE-338: reset token, session ID, invite code, nonce.

Minimum extension:

- 4 CWE classes x 3 prompt variants x 3 conditions x 3 models x 10 trials = 1,080 rows.

Claim impact:

> Moves the paper from six prompt cases toward a small benchmark.

### P5: Cross-Language Cleanup

Current cross-language result is useful but bounded:

- five models completed;
- GPT-5.3 Codex route-error only;
- Python/Go prompts reused partly JavaScript-oriented rule templates.

Action:

1. Write language-specific rules:
   - Python: `ast.literal_eval`, `secrets`, `hashlib` guidance;
   - Go: `crypto/rand`, `net/http` transport, command construction guidance.
2. Recover or replace GPT-5.3 route.
3. Re-run the cross-language subset.

Claim impact:

> Converts the current portability stress test into a real language-generalization result.

### P6: Multi-Turn Agent Workflow

Problem:

Single-turn code generation is not how coding agents are normally used.

Minimal design:

- 2 models;
- 3 CWE tasks;
- 3 conditions;
- 10 trials per cell;
- repository tasks where the agent edits files and produces a patch.

Deliverables:

- `experiments/tasks/agentic-cwe-tasks/`
- `experiments/data/agentic-workflow/`
- patch scanner and task-success labels.

Claim impact:

> Required for a proper full-conference version, but not a Zenodo/JISA blocker.

### P7: Instruction-Decay Follow-Up

The quota incident is useful, but it should not dominate this paper.

Decision:

- Keep it as a short appendix or remove it from venue submissions.
- Treat a controlled decay benchmark as a separate paper.

Separate-paper design:

- state one cost/security constraint once;
- insert 0, 2k, 8k, 32k, 64k distractor tokens;
- ask the model to perform an action that would violate the constraint;
- measure compliance.

Potential title:

**Instruction Decay in Long-Context Coding Agents**

## Venue Roadmap

### Zenodo

Status: done.

- DOI: `10.5281/zenodo.20574220`
- Git tag: `v2.0.0`
- Community submission can be added separately.

### JISA

Best near-term journal route if we keep claims applied and bounded.

Needed:

- stronger detector-validity section;
- neutral/generic control caveat;
- practitioner guidance;
- artifact/reproducibility appendix.

### AISec @ CCS

Best security-workshop route.

Needed:

- ACM format;
- incident appendix shortened or removed;
- control-baseline caveat;
- detector validation table.

### TMLR

Possible, but harder.

Needed:

- anonymization;
- stronger instruction-following framing;
- mixed-effects/Bayesian model;
- incident removed or sharply shortened;
- full-output validation preferred.

### Proper Full Conference

Not recommended yet.

Needed:

- full-output rerun;
- prompt-set expansion;
- multi-turn agent workflow;
- stronger semantic/static analysis;
- cleaner provider-route equivalence.

## Updated Execution Plan

### Phase 1: Make the Current Paper Harder to Reject

Target: AISec/JISA-ready.

1. Run 360-row full-output validation.
2. Add Opus-exclusion sensitivity.
3. Add mixed-effects or Bayesian model if cheap.
4. Update paper limitations and detector-validity section.
5. Produce AISec/JISA draft.

### Phase 2: Upgrade Ecological Validity

Target: stronger conference version.

1. Expand prompt set per CWE.
2. Clean up cross-language rules.
3. Complete or freeze neutral/generic controls.

### Phase 3: Agentic Workflow

Target: proper full-conference version or second paper.

1. Build repository-level tasks.
2. Measure final patch security and task success.
3. Compare rule framings in multi-step agent workflows.

## Decision Gate

| Finding | Decision |
| --- | --- |
| 360-row validation has low patched-detector error | Proceed to AISec/JISA package |
| 360-row validation finds substantial detector errors | Fix detector and rerun before submission |
| Neutral/generic controls match fast-prototype baseline | Main rule effect is robust to control wording |
| Neutral/generic controls sharply reduce vulnerability | Reframe: targeted rules mostly override adversarial control |
| Opus-exclusion sensitivity preserves conclusions | Mixed-provenance concern is neutralized |
| Opus-exclusion changes conclusions | Remove Opus from headline provider-stack claims |
| Mixed-effects model confirms rule effect | Use it as primary model |
| Mixed-effects model weakens polarity equivalence | Reframe polarity as descriptive aggregate only |

## Immediate Next Step

Highest-return next task:

**Build and run the 360-row full-output validation plan.**

Second task in parallel if model budget allows:

**Add Opus-provenance sensitivity analysis without new model calls.**
