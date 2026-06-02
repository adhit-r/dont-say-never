# Submission Checklist

## Paper Claims

- [x] Main claim says rule presence is robust; polarity is not reliable.
- [x] The pilot is described as superseded, not contradicted without explanation.
- [x] The paper does not claim that rule wording never matters.
- [x] The paper does not claim detector validation beyond what artifacts support.
- [x] The instruction-decay incident is marked as a case study, not a general result.
- [x] The pilot 5/10 vs 2/10 cell is no longer described as statistically significant.
- [ ] Title does not imply statistical equivalence unless equivalence testing is added.
- [ ] Abstract says "no consistent aggregate advantage" rather than "polarity does not matter" if submitting to a rigorous venue.
- [ ] Incident case study is appendix-only or separate-paper material unless a controlled decay benchmark is added.

## Dataset

- [x] Final dataset path is `experiments/data/pro-replication/main/`.
- [x] Final dataset contains 6 model files.
- [x] Each final model file has 360 valid rows.
- [x] Total final rows = 2,160.
- [x] Final errors = 0.
- [x] README, abstract, and paper all report 2,160, not 2,004.
- [x] Non-API extension path is `experiments/data/pro-replication/non-api/`.
- [x] Non-API extension contains 1,080 valid rows and 0 errors.
- [x] Non-API claims distinguish formula-evaluation risk from hash/token inertness.

## Figures

- [x] `figures/fig-pro-gpt-vs-claude-bars.png` is regenerated from final data.
- [x] `figures/fig-pro-polarity-heatmap.png` is regenerated from final data.
- [x] `figures/fig-pro-control-baseline-heatmap.png` is regenerated from final data.
- [x] `figures/fig-pro-non-api-control.png` is regenerated from final data.
- [x] Paper `\\includegraphics` paths point to existing files.

## Validation

- [x] Detector-validation sample exists.
- [x] Full-code preservation is enabled for future runs.
- [x] GPT-family full-output validation rerun is summarized.
- [x] Claude-family full-output validation rerun is summarized.
- [x] Combined validation summary reports original vs patched detector behavior.
- [x] Detector limitations are disclosed: prose-only HTTP false positives and `Function(...)` CWE-94 false negatives.
- [x] Paper says original 2,160-row files contain previews only, unless raw full outputs are recovered.
- [x] Patched detector is used for all new non-API, four-arm, or cross-language extensions.
- [ ] Main study has a full-output rerun or the submission explicitly limits claims to detector-counted previews plus validation slices.
- [ ] Semantic detectors are added where practical: AST, Semgrep, ESLint/security rules, or custom taint-style checks.
- [ ] Functional correctness is measured separately from vulnerability labels.
- [ ] Refusal/no-code outputs are reported separately from secure functional outputs.
- [ ] Manual annotation is blinded for at least a stratified sample.

## Controls and Statistics

- [ ] Complete a neutral helpful-assistant control.
- [ ] Keep the current fast-prototyping/no-extra-security control as an adversarial baseline, not the only control.
- [ ] Complete a generic secure-coding control.
- [ ] Add hierarchical logistic regression or Bayesian hierarchical modeling.
- [x] Add confidence intervals/effect sizes for all aggregate claims.
- [x] Add multiple-testing correction for exploratory per-cell tests.
- [ ] Add equivalence testing before making any equivalence claim about positive vs negative framing.
- [ ] Document prompt order/randomization and trial independence assumptions.

## Reproducibility

- [ ] Freeze exact commit hash for submission.
- [ ] Record accepted model IDs, provider routes, CLI/API versions, and decoding settings.
- [ ] Archive exact prompts, system prompts, project rule files, retry logs, and raw outputs where available.
- [ ] Publish a Zenodo v2 artifact bundle with expected hashes and reproduction commands.

## Venue-Specific

### AISec

- [ ] Use ACM sigconf format.
- [ ] Keep main paper focused on security-rule experiment.
- [ ] Move most instruction-decay incident material to appendix.
- [ ] Artifact statement included.
- [ ] AI-use disclosure follows ACM policy.

### TMLR

- [ ] Use TMLR template.
- [ ] Anonymize author, repo, DOI, and incident evidence.
- [ ] Frame as instruction-following behavior, not only secure coding.
- [ ] Remove or shorten case-study section unless a controlled decay experiment is added.

### JISA

- [ ] Expand secure-code-generation related work.
- [ ] Add practitioner guidance.
- [ ] Include artifact/reproducibility appendix.
- [ ] Add detector validation or clearly state validation limitation.

## Release

- [x] Commit final artifacts.
- [ ] Tag a release candidate.
- [ ] Publish Zenodo v2 after paper freeze.
- [ ] Update README DOI note after Zenodo v2 publication.
