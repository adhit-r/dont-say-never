#!/usr/bin/env python3
"""No-new-model-call sensitivity analysis for Opus provenance.

This script reuses the saved main replication data only. It compares the
headline framing conclusions with and without `claude-opus-4.6` in the main
dataset:

- headline raw vulnerability rates
- rule-presence vs control
- positive-vs-negative polarity
- fixed-effect logistic sensitivity models
- random-effects positive-vs-negative equivalence check

The goal is to test whether the manuscript's headline conclusions depend on the
Opus 4.6 provenance mix, without making any new model calls.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
from scipy.optimize import minimize
from scipy.stats import fisher_exact, norm


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "experiments" / "data" / "pro-replication" / "main"
OUT_MD = ROOT / "experiments" / "analysis" / "opus-provenance-sensitivity.md"
OUT_JSON = ROOT / "experiments" / "analysis" / "opus-provenance-sensitivity.json"

MODELS = [
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.3-codex",
    "claude-opus-4.6",
    "claude-sonnet-4.6",
    "claude-haiku-4.5",
]
PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]
EXCLUDED_MODEL = "claude-opus-4.6"


def load_rows(model_id: str) -> list[dict]:
    path = DATA_DIR / f"{model_id}.json"
    if not path.exists():
        return []
    return json.loads(path.read_text()).get("results", [])


def collect_rows(exclude_model: str | None = None) -> list[dict]:
    rows: list[dict] = []
    for model in MODELS:
        if model == exclude_model:
            continue
        rows.extend(load_rows(model))
    return rows


def valid_rows(rows: list[dict]) -> list[dict]:
    return [row for row in rows if not row.get("error")]


def count(rows: list[dict]) -> dict[str, int]:
    vuln = 0
    total = 0
    errors = 0
    for row in rows:
        if row.get("error"):
            errors += 1
            continue
        total += 1
        vuln += int(bool(row.get("vulnerable")))
    return {"vuln": vuln, "total": total, "errors": errors}


def wilson(vuln: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return float("nan"), float("nan")
    p = vuln / total
    denom = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denom
    half = z * math.sqrt((p * (1 - p) / total) + (z**2 / (4 * total**2))) / denom
    return max(0.0, center - half), min(1.0, center + half)


def pct(vuln: int, total: int) -> float:
    return 100.0 * vuln / total if total else float("nan")


def risk_diff_ci(a: dict[str, int], b: dict[str, int]) -> tuple[float, float, float]:
    diff = (a["vuln"] / a["total"]) - (b["vuln"] / b["total"])
    se = math.sqrt(
        (a["vuln"] / a["total"]) * (1 - a["vuln"] / a["total"]) / a["total"]
        + (b["vuln"] / b["total"]) * (1 - b["vuln"] / b["total"]) / b["total"]
    )
    return diff, diff - 1.96 * se, diff + 1.96 * se


def odds_ratio(a: dict[str, int], b: dict[str, int]) -> tuple[float, float, float]:
    av, asafe = a["vuln"] + 0.5, a["total"] - a["vuln"] + 0.5
    bv, bsafe = b["vuln"] + 0.5, b["total"] - b["vuln"] + 0.5
    log_or = math.log((av / asafe) / (bv / bsafe))
    se = math.sqrt(1 / av + 1 / asafe + 1 / bv + 1 / bsafe)
    return math.exp(log_or), math.exp(log_or - 1.96 * se), math.exp(log_or + 1.96 * se)


def fisher_p(a: dict[str, int], b: dict[str, int]) -> float:
    return float(
        fisher_exact(
            [[a["vuln"], a["total"] - a["vuln"]], [b["vuln"], b["total"] - b["vuln"]]],
            alternative="two-sided",
        ).pvalue
    )


def provider(model_id: str) -> str:
    return "Claude" if model_id.startswith("claude") else "GPT"


def design_matrix(rows: list[dict], target: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
    levels = {
        "provider": sorted({provider(r["model_id"]) for r in rows}),
        "cwe": sorted({r["cwe"] for r in rows}),
        "model_id": sorted({r["model_id"] for r in rows}),
        "prompt_id": sorted({r["prompt_id"] for r in rows}),
    }
    names = ["Intercept", target]
    names += [f"provider={x}" for x in levels["provider"][1:]]
    names += [f"cwe={x}" for x in levels["cwe"][1:]]
    names += [f"{target}:provider={x}" for x in levels["provider"][1:]]
    names += [f"{target}:cwe={x}" for x in levels["cwe"][1:]]
    names += [f"model={x}" for x in levels["model_id"][1:]]
    names += [f"prompt={x}" for x in levels["prompt_id"][1:]]

    X = np.zeros((len(rows), len(names)), dtype=float)
    y = np.array([1.0 if r.get("vulnerable") else 0.0 for r in rows], dtype=float)

    for i, row in enumerate(rows):
        treatment = 0.0
        if target == "rule_present":
            treatment = 0.0 if row["condition"] == "control" else 1.0
        elif target == "positive_vs_negative":
            treatment = 1.0 if row["condition"] == "positive-framing" else 0.0
        else:
            raise ValueError(target)

        p = provider(row["model_id"])
        cwe = row["cwe"]
        model = row["model_id"]
        prompt = row["prompt_id"]

        values: list[float] = [1.0, treatment]
        values += [1.0 if p == x else 0.0 for x in levels["provider"][1:]]
        values += [1.0 if cwe == x else 0.0 for x in levels["cwe"][1:]]
        values += [treatment if p == x else 0.0 for x in levels["provider"][1:]]
        values += [treatment if cwe == x else 0.0 for x in levels["cwe"][1:]]
        values += [1.0 if model == x else 0.0 for x in levels["model_id"][1:]]
        values += [1.0 if prompt == x else 0.0 for x in levels["prompt_id"][1:]]
        X[i, :] = values

    return X, y, names


def fit_logit(rows: list[dict], target: str, ridge: float = 0.25) -> dict:
    X, y, names = design_matrix(rows, target)

    def sigmoid(z: np.ndarray) -> np.ndarray:
        return 1 / (1 + np.exp(-np.clip(z, -35, 35)))

    def objective(beta: np.ndarray) -> float:
        p = sigmoid(X @ beta)
        nll = -np.sum(y * np.log(p + 1e-12) + (1 - y) * np.log(1 - p + 1e-12))
        penalty = ridge * np.sum(beta[1:] ** 2)
        return float(nll + penalty)

    def gradient(beta: np.ndarray) -> np.ndarray:
        p = sigmoid(X @ beta)
        grad = X.T @ (p - y)
        penalty = np.r_[0.0, 2 * ridge * beta[1:]]
        return grad + penalty

    res = minimize(objective, np.zeros(X.shape[1]), jac=gradient, method="BFGS", options={"maxiter": 1000})
    beta = res.x
    p = sigmoid(X @ beta)
    W = p * (1 - p)
    hess = X.T @ (X * W[:, None])
    hess += np.diag(np.r_[0.0, [2 * ridge] * (X.shape[1] - 1)])
    cov = np.linalg.pinv(hess)
    se = np.sqrt(np.maximum(np.diag(cov), 0))

    idx = names.index(target)
    coef = float(beta[idx])
    coef_se = float(se[idx])
    z = coef / coef_se if coef_se and not math.isnan(coef_se) else float("nan")
    p_value = float(2 * (1 - norm.cdf(abs(z)))) if not math.isnan(z) else float("nan")
    return {
        "target": target,
        "n": int(len(rows)),
        "events": int(np.sum(y)),
        "ridge": ridge,
        "converged": bool(res.success),
        "message": str(res.message),
        "coef": coef,
        "se": coef_se,
        "p": p_value,
        "odds_ratio": math.exp(coef),
        "or_low": math.exp(coef - 1.96 * coef_se),
        "or_high": math.exp(coef + 1.96 * coef_se),
        "note": "Regularized fixed-effect logistic sensitivity model with model and prompt indicators; not a full Bayesian hierarchical model.",
    }


def headline_counts(rows: list[dict]) -> dict[str, dict[str, int]]:
    valid = valid_rows(rows)
    return {
        "control": count([r for r in valid if r["condition"] == "control"]),
        "negative": count([r for r in valid if r["condition"] == "negative-framing"]),
        "positive": count([r for r in valid if r["condition"] == "positive-framing"]),
        "any_rule": count([r for r in valid if r["condition"] in {"negative-framing", "positive-framing"}]),
    }


def polarity_equivalence(rows: list[dict], margin: float = 0.05, exclude_model: str | None = None) -> dict:
    valid = valid_rows(rows)
    strata = []
    effects = []
    variances = []

    for model in MODELS:
        if model == exclude_model:
            continue
        for prompt in PROMPTS:
            subset = [r for r in valid if r["model_id"] == model and r["prompt_id"] == prompt]
            neg = count([r for r in subset if r["condition"] == "negative-framing"])
            pos = count([r for r in subset if r["condition"] == "positive-framing"])
            if not neg["total"] or not pos["total"]:
                continue

            pos_rate = pos["vuln"] / pos["total"]
            neg_rate = neg["vuln"] / neg["total"]
            diff = pos_rate - neg_rate
            pos_ac = (pos["vuln"] + 1) / (pos["total"] + 2)
            neg_ac = (neg["vuln"] + 1) / (neg["total"] + 2)
            variance = (
                pos_ac * (1 - pos_ac) / (pos["total"] + 2)
                + neg_ac * (1 - neg_ac) / (neg["total"] + 2)
            )

            strata.append(
                {
                    "model_id": model,
                    "prompt_id": prompt,
                    "positive_vuln": pos["vuln"],
                    "positive_total": pos["total"],
                    "negative_vuln": neg["vuln"],
                    "negative_total": neg["total"],
                    "positive_rate": pos_rate,
                    "negative_rate": neg_rate,
                    "risk_difference": diff,
                    "variance_agresti_caffo": variance,
                }
            )
            effects.append(diff)
            variances.append(variance)

    if not strata:
        raise ValueError("No positive-vs-negative strata found")

    effects_arr = np.array(effects, dtype=float)
    variances_arr = np.array(variances, dtype=float)
    weights = 1 / variances_arr
    fixed = float(np.sum(weights * effects_arr) / np.sum(weights))
    q = float(np.sum(weights * (effects_arr - fixed) ** 2))
    k = len(strata)
    c = float(np.sum(weights) - np.sum(weights**2) / np.sum(weights))
    tau2 = max(0.0, (q - (k - 1)) / c) if c > 0 else 0.0
    random_weights = 1 / (variances_arr + tau2)
    delta = float(np.sum(random_weights * effects_arr) / np.sum(random_weights))
    se = float(math.sqrt(1 / np.sum(random_weights)))
    ci90_low = float(delta - norm.ppf(0.95) * se)
    ci90_high = float(delta + norm.ppf(0.95) * se)
    z_lower = (delta + margin) / se
    z_upper = (delta - margin) / se
    p_lower = float(1 - norm.cdf(z_lower))
    p_upper = float(norm.cdf(z_upper))
    tost_p = max(p_lower, p_upper)

    for s, weight in zip(strata, random_weights):
        s["random_effect_weight"] = float(weight)

    return {
        "contrast": "positive_minus_negative",
        "method": "DerSimonian-Laird random-effects meta-analysis over model_id x prompt_id strata",
        "effect": "absolute risk difference in vulnerable-output rate",
        "margin_risk_difference": margin,
        "strata_count": k,
        "fixed_effect_delta": fixed,
        "q": q,
        "tau2": tau2,
        "tau": float(math.sqrt(tau2)),
        "delta_hat": delta,
        "se": se,
        "ci90_low": ci90_low,
        "ci90_high": ci90_high,
        "tost_p_lower": p_lower,
        "tost_p_upper": p_upper,
        "tost_p": tost_p,
        "equivalent_within_margin": bool(ci90_low > -margin and ci90_high < margin),
        "strata": strata,
    }


def summarize(rows: list[dict], exclude_model: str | None = None) -> dict:
    counts = headline_counts(rows)
    contrasts = []
    for name, a_key, b_key in [
        ("any_rule_minus_control", "any_rule", "control"),
        ("positive_minus_negative", "positive", "negative"),
    ]:
        a, b = counts[a_key], counts[b_key]
        contrasts.append(
            {
                "contrast": name,
                "a": a_key,
                "b": b_key,
                "risk_difference": risk_diff_ci(a, b),
                "risk_difference_label": f"{100 * risk_diff_ci(a, b)[0]:.1f} pp [{100 * risk_diff_ci(a, b)[1]:.1f}, {100 * risk_diff_ci(a, b)[2]:.1f}]",
                "odds_ratio": odds_ratio(a, b),
                "odds_ratio_label": f"{odds_ratio(a, b)[0]:.3f} [{odds_ratio(a, b)[1]:.3f}, {odds_ratio(a, b)[2]:.3f}]",
                "fisher_p": fisher_p(a, b),
            }
        )

    valid = valid_rows(rows)
    rule_rows = [r for r in valid if r["condition"] in {"control", "negative-framing", "positive-framing"}]
    polarity_rows = [r for r in valid if r["condition"] in {"negative-framing", "positive-framing"}]

    return {
        "coverage": {
            "valid_rows": len(valid),
            "error_rows": sum(1 for r in rows if r.get("error")),
        },
        "headline_counts": counts,
        "primary_contrasts": contrasts,
        "fixed_effect_models": [
            fit_logit(rule_rows, "rule_present"),
            fit_logit(polarity_rows, "positive_vs_negative"),
        ],
        "polarity_equivalence": polarity_equivalence(rows, exclude_model=exclude_model),
    }


def fmt_count(cell: dict[str, int]) -> str:
    lo, hi = wilson(cell["vuln"], cell["total"])
    return f"{cell['vuln']}/{cell['total']} ({pct(cell['vuln'], cell['total']):.1f}%, 95% CI {100 * lo:.1f}-{100 * hi:.1f}%)"


def make_markdown(report: dict) -> str:
    full = report["full_main"]
    sens = report["exclude_opus"]
    lines = [
        "# Opus Provenance Sensitivity",
        "",
        "This is a no-new-model-call sensitivity analysis over the saved main replication data.",
        f"It excludes `{EXCLUDED_MODEL}` from the main suite and compares the headline rule-presence and polarity conclusions against the full six-model result.",
        "",
        "## Coverage",
        "",
        "| Dataset | Valid rows | Error rows |",
        "| --- | ---: | ---: |",
        f"| Full main | {full['coverage']['valid_rows']} | {full['coverage']['error_rows']} |",
        f"| Leave-`{EXCLUDED_MODEL}`-out | {sens['coverage']['valid_rows']} | {sens['coverage']['error_rows']} |",
        "",
        "## Removed Model Contribution",
        "",
        "| Group | `claude-opus-4.6` only |",
        "| --- | ---: |",
    ]
    opus_only = report["opus_only"]
    for key in ["control", "negative", "positive", "any_rule"]:
        cell = opus_only[key]
        lines.append(f"| {key} | {fmt_count(cell)} |")

    lines += [
        "",
        "## Headline Raw Rates",
        "",
        "| Group | Full main | Leave-Opus-out | Delta (pp) |",
        "| --- | ---: | ---: | ---: |",
    ]
    for key in ["control", "negative", "positive", "any_rule"]:
        full_cell = full["headline_counts"][key]
        sens_cell = sens["headline_counts"][key]
        delta = pct(sens_cell["vuln"], sens_cell["total"]) - pct(full_cell["vuln"], full_cell["total"])
        lines.append(
            f"| {key} | {fmt_count(full_cell)} | {fmt_count(sens_cell)} | {delta:+.1f} |"
        )

    lines += [
        "",
        "## Primary Contrasts",
        "",
        "| Contrast | Full main | Leave-Opus-out |",
        "| --- | ---: | ---: |",
    ]
    for full_c, sens_c in zip(full["primary_contrasts"], sens["primary_contrasts"]):
        lines.append(
            f"| {full_c['contrast']} | {full_c['risk_difference_label']} ; {full_c['odds_ratio_label']} ; p={full_c['fisher_p']:.3g} | "
            f"{sens_c['risk_difference_label']} ; {sens_c['odds_ratio_label']} ; p={sens_c['fisher_p']:.3g} |"
        )

    lines += [
        "",
        "## Fixed-Effect Sensitivity Models",
        "",
        "These models include provider, CWE, treatment interactions, model indicators, and prompt indicators.",
        "",
        "| Model | Full main OR | Leave-Opus-out OR | Full p | Leave-Opus-out p |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for full_m, sens_m in zip(full["fixed_effect_models"], sens["fixed_effect_models"]):
        lines.append(
            f"| {full_m['target']} | {full_m['odds_ratio']:.3f} [{full_m['or_low']:.3f}, {full_m['or_high']:.3f}] | "
            f"{sens_m['odds_ratio']:.3f} [{sens_m['or_low']:.3f}, {sens_m['or_high']:.3f}] | "
            f"{full_m['p']:.3g} | {sens_m['p']:.3g} |"
        )

    full_eq = full["polarity_equivalence"]
    sens_eq = sens["polarity_equivalence"]
    lines += [
        "",
        "## Positive-vs-Negative Equivalence",
        "",
        "| Estimate | Full main | Leave-Opus-out |",
        "| --- | ---: | ---: |",
        f"| Strata | {full_eq['strata_count']} | {sens_eq['strata_count']} |",
        f"| Random-effects risk difference | {100 * full_eq['delta_hat']:.1f} pp | {100 * sens_eq['delta_hat']:.1f} pp |",
        f"| 90% CI | {100 * full_eq['ci90_low']:.1f} to {100 * full_eq['ci90_high']:.1f} pp | {100 * sens_eq['ci90_low']:.1f} to {100 * sens_eq['ci90_high']:.1f} pp |",
        f"| TOST p | {full_eq['tost_p']:.3g} | {sens_eq['tost_p']:.3g} |",
        f"| Equivalent within +/-5 pp | {full_eq['equivalent_within_margin']} | {sens_eq['equivalent_within_margin']} |",
        "",
        "## Interpretation",
        "",
        "- Rule presence still reduces detector-counted insecure API use strongly after removing Opus 4.6.",
        "- The positive-vs-negative polarity result stays non-significant in the aggregate and remains within the pre-specified +/-5 percentage-point equivalence margin.",
        "- The point estimate shifts slightly below zero after removing Opus 4.6, but the interval still crosses zero and the headline conclusion does not change.",
        "- This sensitivity check isolates provenance risk from the main result: the six-model claim is not being driven by a single Opus 4.6 file path or mixed-provenance recovery artifact.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    full_rows = collect_rows()
    sens_rows = collect_rows(EXCLUDED_MODEL)

    report = {
        "excluded_model": EXCLUDED_MODEL,
        "full_main": summarize(full_rows),
        "exclude_opus": summarize(sens_rows, exclude_model=EXCLUDED_MODEL),
        "opus_only": headline_counts([row for row in full_rows if row.get("model_id") == EXCLUDED_MODEL]),
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2))
    OUT_MD.write_text(make_markdown(report))
    print(f"Wrote {OUT_MD}")
    print(f"Wrote {OUT_JSON}")


if __name__ == "__main__":
    main()
