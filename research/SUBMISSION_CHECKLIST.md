# Submission Checklist

## Paper Claims

- [ ] Main claim says rule presence is robust; polarity is not reliable.
- [ ] The pilot is described as superseded, not contradicted without explanation.
- [ ] The paper does not claim that rule wording never matters.
- [ ] The paper does not claim detector validation beyond what artifacts support.
- [ ] The instruction-decay incident is marked as a case study, not a general result.

## Dataset

- [ ] Final dataset path is `experiments/data/pro-replication/main/`.
- [ ] Final dataset contains 6 model files.
- [ ] Each final model file has 360 valid rows.
- [ ] Total final rows = 2,160.
- [ ] Final errors = 0.
- [ ] README, abstract, and paper all report 2,160, not 2,004.
- [ ] Non-API extension path is `experiments/data/pro-replication/non-api/`.
- [ ] Non-API extension contains 1,080 valid rows and 0 errors.
- [ ] Non-API claims distinguish formula-evaluation risk from hash/token inertness.

## Figures

- [ ] `figures/fig-pro-gpt-vs-claude-bars.png` is regenerated from final data.
- [ ] `figures/fig-pro-polarity-heatmap.png` is regenerated from final data.
- [ ] `figures/fig-pro-control-baseline-heatmap.png` is regenerated from final data.
- [ ] `figures/fig-pro-non-api-control.png` is regenerated from final data.
- [ ] Paper `\\includegraphics` paths point to existing files.

## Validation

- [ ] Detector-validation sample exists.
- [ ] Full-code preservation is enabled for future runs.
- [ ] GPT-family full-output validation rerun is summarized.
- [ ] Claude-family full-output validation rerun is summarized.
- [ ] Combined validation summary reports original vs patched detector behavior.
- [ ] Detector limitations are disclosed: prose-only HTTP false positives and `Function(...)` CWE-94 false negatives.
- [ ] Paper says original 2,160-row files contain previews only, unless raw full outputs are recovered.
- [ ] Patched detector is used for all new non-API, four-arm, or cross-language extensions.

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

- [ ] Commit final artifacts.
- [ ] Tag a release candidate.
- [ ] Publish Zenodo v2 after paper freeze.
- [ ] Update README DOI note after Zenodo v2 publication.
