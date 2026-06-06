# Hierarchical Robustness Analysis

No new model calls were made for this check.
The main 2,160-row pro replication was stratified by model-prompt cell and analyzed with a bootstrap over the 36 strata.
Because each stratum is balanced by design, the stratified mean risk difference matches the pooled row-level difference, but the bootstrap quantifies uncertainty at the model-prompt level.

## Coverage

- Rows: 2160
- Errors: 0
- Strata: 36

## Stratified Results

| Contrast | Stratified risk difference | MH common OR | Strata sign summary |
| --- | ---: | ---: | ---: |
| Rule injection vs control | -45.8 pp [-58.5, -33.3] | 0.056 [0.028, 0.101] | 30/4/2 |
| Positive vs negative | 1.7 pp [-3.1, 6.4] | 1.255 [0.647, 2.590] | 7/20/9 |

Interpretation:

- The rule-injection effect remains strongly negative after stratifying by model and prompt. Its bootstrap interval stays entirely below zero, and the common odds ratio stays well below 1.
- The positive-vs-negative contrast stays null-compatible under the same stratification. Its bootstrap interval crosses zero, and the common odds ratio crosses 1.

## Notes

- Stratification unit: model_id x prompt_id.
- Bootstrap: 20,000 resamples over strata, seed 0.
- Sign summary is negative/zero/positive counts across the 36 strata.
