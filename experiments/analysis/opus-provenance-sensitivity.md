# Opus Provenance Sensitivity

This is a no-new-model-call sensitivity analysis over the saved main replication data.
It excludes `claude-opus-4.6` from the main suite and compares the headline rule-presence and polarity conclusions against the full six-model result.

## Coverage

| Dataset | Valid rows | Error rows |
| --- | ---: | ---: |
| Full main | 2160 | 0 |
| Leave-`claude-opus-4.6`-out | 1800 | 0 |

## Removed Model Contribution

| Group | `claude-opus-4.6` only |
| --- | ---: |
| control | 58/120 (48.3%, 95% CI 39.6-57.2%) |
| negative | 0/120 (0.0%, 95% CI 0.0-3.1%) |
| positive | 4/120 (3.3%, 95% CI 1.3-8.3%) |
| any_rule | 4/240 (1.7%, 95% CI 0.6-4.2%) |

## Headline Raw Rates

| Group | Full main | Leave-Opus-out | Delta (pp) |
| --- | ---: | ---: | ---: |
| control | 445/720 (61.8%, 95% CI 58.2-65.3%) | 387/600 (64.5%, 95% CI 60.6-68.2%) | +2.7 |
| negative | 109/720 (15.1%, 95% CI 12.7-17.9%) | 109/600 (18.2%, 95% CI 15.3-21.5%) | +3.0 |
| positive | 121/720 (16.8%, 95% CI 14.3-19.7%) | 117/600 (19.5%, 95% CI 16.5-22.9%) | +2.7 |
| any_rule | 230/1440 (16.0%, 95% CI 14.2-18.0%) | 226/1200 (18.8%, 95% CI 16.7-21.1%) | +2.9 |

## Primary Contrasts

| Contrast | Full main | Leave-Opus-out |
| --- | ---: | ---: |
| any_rule_minus_control | -45.8 pp [-49.9, -41.8] ; 0.118 [0.096, 0.145] ; p=6.27e-102 | -45.7 pp [-50.1, -41.2] ; 0.128 [0.103, 0.160] ; p=1.45e-81 |
| positive_minus_negative | 1.7 pp [-2.1, 5.5] ; 1.132 [0.854, 1.500] ; p=0.429 | 1.3 pp [-3.1, 5.8] ; 1.091 [0.817, 1.456] ; p=0.605 |

## Fixed-Effect Sensitivity Models

These models include provider, CWE, treatment interactions, model indicators, and prompt indicators.

| Model | Full main OR | Leave-Opus-out OR | Full p | Leave-Opus-out p |
| --- | ---: | ---: | ---: | ---: |
| rule_present | 0.311 [0.186, 0.522] | 0.294 [0.163, 0.529] | 9.63e-06 | 4.48e-05 |
| positive_vs_negative | 1.011 [0.549, 1.862] | 0.826 [0.438, 1.555] | 0.973 | 0.553 |

## Positive-vs-Negative Equivalence

| Estimate | Full main | Leave-Opus-out |
| --- | ---: | ---: |
| Strata | 36 | 30 |
| Random-effects risk difference | 1.2 pp | 1.0 pp |
| 90% CI | -1.5 to 3.9 pp | -2.2 to 4.3 pp |
| TOST p | 0.00952 | 0.0219 |
| Equivalent within +/-5 pp | True | True |

## Interpretation

- Rule presence still reduces detector-counted insecure API use strongly after removing Opus 4.6.
- The positive-vs-negative polarity result stays non-significant in the aggregate and remains within the pre-specified +/-5 percentage-point equivalence margin.
- The point estimate shifts slightly below zero after removing Opus 4.6, but the interval still crosses zero and the headline conclusion does not change.
- This sensitivity check isolates provenance risk from the main result: the six-model claim is not being driven by a single Opus 4.6 file path or mixed-provenance recovery artifact.
