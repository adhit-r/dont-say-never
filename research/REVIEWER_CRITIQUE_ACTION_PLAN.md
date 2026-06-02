# Reviewer Critique Action Plan

Date: 2026-06-02

Source: reviewer-style critique provided in `Pasted text.txt`.

## Current Verdict

The paper is promising empirical work, but not submission-ready for a top-tier ML/security venue in its current form. The strongest current contribution is a large replication showing that targeted security rules reduce insecure API use across six coding-agent models, while positive framing has no consistent aggregate advantage over prohibition framing in this benchmark.

The paper becomes much stronger if it is framed as:

> Security rules reduce detector-counted insecure API use; positive framing has no consistent aggregate advantage in this benchmark.

Avoid stronger claims such as:

- polarity does not matter or is equivalent across models;
- rules reliably improve real-world secure coding;
- the pilot proved prohibition backfire;
- instruction decay is established from the Copilot quota incident.

## Critical Fixes Before Any Submission

| Priority | Issue | Current risk | Required action | Status |
| --- | --- | --- | --- | --- |
| P0 | Incorrect pilot p-value | The manuscript reported the 5/10 vs 2/10 pilot cell as Fisher `p=0.016`; the stated table gives two-sided `p approx. 0.350` and one-sided `p approx. 0.175`. | Correct all manuscript text. Treat the pilot cell as a descriptive anomaly and motivation only. | Done in current drafts |
| P0 | Main 2,160 outputs preserve previews only | The main dataset cannot be fully audited, compiled, or semantically analyzed. | Either full-output rerun the main study or clearly keep the paper bounded to detector-counted code previews plus validation slices. | Open |
| P0 | Control prompt discourages security | The control says not to add validation/security unless asked, so rule effects partly measure override of an anti-security baseline. | Add neutral helpful-control and generic-security-control baselines before claiming ordinary coding-agent security improvement. | Open |
| P1 | Regex-only vulnerability labels | Detector audit already found 5 FP and 3 FN in 60 reruns. | Add AST/Semgrep/custom semantic detectors and report manual blind annotation. | Open |
| P1 | No functional correctness metric | A secure response may be refusal-only or non-functional. | Report joint outcomes: secure+functional, secure+non-functional, refusal/no-code, vulnerable+functional, vulnerable+non-functional. | Open |
| P1 | Title overclaims | "Polarity Doesn't" sounds like equivalence, but the evidence supports no consistent aggregate advantage. | Retitle to a narrower claim. | Done in current drafts |
| P1 | Route confound in extensions | Some Claude extension data used OpenRouter while main Claude runs used Claude CLI. | Mark extensions as route-confounded, or rerun a same-route subset. | Open |
| P1 | Incident case study dominates | The quota incident is one case and can distract from the main experiment. | Move to appendix or split into a separate instruction-decay paper unless a controlled decay benchmark is run. | Open |

## Recommended Title Boundary

Recommended title for submission:

**Targeted Security Rules Reduce Insecure API Use in LLM Coding Agents: A Multi-Model Study of Positive vs. Prohibition Framing**

Why:

- Keeps the positive contribution.
- Avoids implying statistical equivalence.
- Makes the benchmark boundary explicit.
- Avoids contradicting the CodeCoach paper's claim that persistent rule files are a useful security mechanism.

## Methodology Additions

### Control Conditions

Add three baselines:

1. Neutral helpful assistant:
   - no security discouragement;
   - ordinary coding assistant behavior.
2. Current fast-prototyping control:
   - retain as adversarial/no-extra-security baseline.
3. Generic secure coding control:
   - "write secure code and avoid common vulnerabilities";
   - tests whether CWE-specific rules outperform generic security prompting.

This separates:

- effect of any security instruction;
- effect of CWE-specific persistent rules;
- effect of overriding an anti-security control.

### Full-Output Rerun

Highest-value rerun if budget permits:

- Preserve full raw output and extracted code for every row.
- Record prompt, system/rule text, model route, exact accepted model ID, CLI/API version, decoding settings, retry logs, elapsed time, and detector label.
- Use the patched detector from the start.

Minimum acceptable alternative:

- Full-output stratified rerun of 360 rows;
- blind manual annotation;
- same patched detector;
- report label uncertainty and do not claim full-dataset semantic precision.

### Functional Correctness

For every generated output, classify:

- refusal/no-code;
- code-only but uncompilable;
- compilable but task-failing;
- task-satisfying and secure;
- task-satisfying and vulnerable.

Suggested checks:

- TypeScript/JavaScript: parse with `tsc` or `eslint`, then run task-specific unit tests.
- Python: parse with `ast`, run minimal unit tests.
- Go: `go test` or `go vet` for generated snippets where feasible.

### Semantic Security Detection

Move beyond regex where possible:

- JavaScript/TypeScript:
  - detect `eval`, `Function`, `setTimeout(string)`, `setInterval(string)`;
  - detect weak hash wrappers;
  - detect `http://` only inside generated code, not refusal prose;
  - detect shell interpolation and unsafe subprocess invocation.
- Python:
  - `eval`, `exec`, `compile`, dynamic import abuse;
  - `hashlib.md5`;
  - `random` for security-token tasks.
- Go:
  - shell command construction;
  - insecure HTTP transport;
  - weak randomness where applicable.

Use Semgrep/custom AST rules where practical. Keep regex as a fallback detector, not the sole labeler.

## Statistical Additions

### Correct the Pilot

The pilot's 5/10 vs 2/10 table is not significant:

- Fisher two-sided: `p approx. 0.350`
- Fisher one-sided greater: `p approx. 0.175`

Use this as a self-correction point, not a weakness to hide.

### Avoid Non-Significance as Equivalence

Current claim should be:

> Positive framing showed no consistent aggregate advantage over negative framing in this benchmark.

Do not claim:

> Positive and negative framing are equivalent.

To make equivalence claims, add:

- pre-specified smallest effect size of interest;
- two one-sided tests or Bayesian equivalence analysis;
- confidence intervals for risk differences and Cohen's h.

### Hierarchical Model

Add a mixed-effects logistic regression or Bayesian hierarchical model:

```text
vulnerable ~ condition + provider + cwe + api_named + language
           + condition:provider + condition:cwe
           + (1 | model) + (1 | prompt)
```

Report:

- fixed effect for any rule vs control;
- fixed effect for positive vs negative;
- model/prompt random effects;
- credible/confidence intervals;
- interaction terms for prompt class and provider stack.

### Multiple Testing

For per-cell Fisher tests:

- report uncorrected p-values only as exploratory;
- add FDR or Bonferroni correction;
- emphasize aggregate/hierarchical estimates over cherry-picked cell tests.

## Reproducibility Package

Create a frozen artifact bundle before Zenodo v2:

- exact commit hash;
- archived dataset with full outputs where available;
- exact prompts and rule files;
- accepted model IDs and provider routes;
- CLI/API versions;
- decoding settings;
- randomization/order policy;
- retry/error logs;
- raw API/CLI outputs where permitted;
- detector scripts;
- figure scripts;
- statistical scripts;
- manual annotation guidelines;
- sampled manual labels;
- reproduction commands;
- expected hashes for core outputs.

## Security Robustness Additions

Track these as future detector and prompt extensions:

- SQL injection;
- path traversal;
- command injection;
- SSRF;
- XSS;
- insecure deserialization;
- auth bypass;
- hardcoded secrets;
- unsafe YAML/XML parsing;
- shell interpolation;
- weak randomness through non-obvious APIs;
- wrapper functions around banned APIs.

## Recommended Roadmap Order

1. Correct the pilot p-value and all claim boundaries.
2. Add neutral and generic-security controls.
3. Add full-output preservation and functional correctness checks.
4. Add semantic detector validation and blind manual labels.
5. Add hierarchical/equivalence statistics.
6. Move the incident case study to appendix or separate paper.
7. Freeze artifact bundle and publish Zenodo v2.

## Reviewer-Ready Claim

Use this claim boundary in abstracts and talks:

> In a six-model benchmark of vulnerability-eliciting coding tasks, persistent CWE-specific security rules substantially reduce insecure API use. We do not find a consistent aggregate advantage for positive safe-alternative framing over prohibition framing. The practical recommendation is to write concrete, testable, CWE-specific rules and validate them on the target agent stack rather than relying on a universal "never say never" heuristic.
