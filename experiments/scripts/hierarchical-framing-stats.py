#!/usr/bin/env python3
"""Statistics companion for the pro replication study.

The report is intentionally dependency-light: scipy/numpy only. It provides
the reviewer-facing pieces missing from the original aggregate summaries:

- Wilson confidence intervals for headline rates.
- Fisher exact tests with Benjamini-Hochberg FDR correction for exploratory
  per-cell tests.
- Haldane-corrected odds ratios and risk differences for headline contrasts.
- Regularized fixed-effect logistic models with model and prompt controls.

The fixed-effect models are a pragmatic approximation, not a full Bayesian
hierarchical model. The output says this explicitly so the manuscript does not
overclaim.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
from scipy.optimize import minimize
from scipy.stats import fisher_exact, norm


ROOT = Path(__file__).resolve().parents[2]
DATA_ROOT = ROOT / "experiments" / "data" / "pro-replication"
OUT_MD = ROOT / "experiments" / "analysis" / "hierarchical-framing-stats.md"
OUT_JSON = ROOT / "experiments" / "analysis" / "hierarchical-framing-stats.json"

MODELS = [
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.3-codex",
    "claude-opus-4.6",
    "claude-sonnet-4.6",
    "claude-haiku-4.5",
]
MAIN_PROMPTS = ["eval-usage", "md5-hash", "http-url", "insecure-random", "eval-dynamic", "weak-hash"]


@dataclass
class Count:
    vuln: int = 0
    total: int = 0
    errors: int = 0

    @property
    def safe(self) -> int:
        return self.total - self.vuln

    @property
    def rate(self) -> float:
        return self.vuln / self.total if self.total else float("nan")


def load_suite(suite: str, models: Iterable[str] = MODELS) -> list[dict]:
    rows: list[dict] = []
    for model in models:
        path = DATA_ROOT / suite / f"{model}.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text())
        for row in payload.get("results", []):
            copied = dict(row)
            copied["suite"] = suite
            rows.append(copied)
    return rows


def valid_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if not r.get("error")]


def count(rows: Iterable[dict]) -> Count:
    c = Count()
    for row in rows:
        if row.get("error"):
            c.errors += 1
            continue
        c.total += 1
        c.vuln += int(bool(row.get("vulnerable")))
    return c


def wilson(vuln: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total == 0:
        return (float("nan"), float("nan"))
    p = vuln / total
    denom = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denom
    half = z * math.sqrt((p * (1 - p) / total) + (z**2 / (4 * total**2))) / denom
    return max(0.0, center - half), min(1.0, center + half)


def risk_diff_ci(a: Count, b: Count) -> tuple[float, float, float]:
    """Return a.rate - b.rate and a simple Wald CI.

    This is used for headline orientation only; Wilson intervals are reported
    for raw rates. The markdown labels this as approximate.
    """
    diff = a.rate - b.rate
    se = math.sqrt((a.rate * (1 - a.rate) / a.total) + (b.rate * (1 - b.rate) / b.total))
    return diff, diff - 1.96 * se, diff + 1.96 * se


def odds_ratio(a: Count, b: Count) -> tuple[float, float, float]:
    """Haldane-corrected OR for vulnerable outcome in group a vs group b."""
    av, asafe = a.vuln + 0.5, a.safe + 0.5
    bv, bsafe = b.vuln + 0.5, b.safe + 0.5
    log_or = math.log((av / asafe) / (bv / bsafe))
    se = math.sqrt(1 / av + 1 / asafe + 1 / bv + 1 / bsafe)
    return math.exp(log_or), math.exp(log_or - 1.96 * se), math.exp(log_or + 1.96 * se)


def fisher(a: Count, b: Count) -> float:
    return float(fisher_exact([[a.vuln, a.safe], [b.vuln, b.safe]], alternative="two-sided").pvalue)


def bh_fdr(pvalues: list[float]) -> list[float]:
    n = len(pvalues)
    indexed = sorted(enumerate(pvalues), key=lambda item: item[1])
    q = [1.0] * n
    prev = 1.0
    for rank, (idx, p) in reversed(list(enumerate(indexed, start=1))):
        val = min(prev, p * n / rank)
        q[idx] = val
        prev = val
    return q


def provider(model_id: str) -> str:
    return "Claude" if model_id.startswith("claude") else "GPT"


def design_matrix(rows: list[dict], target: str) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Build a regularized fixed-effect design matrix.

    target is either `rule_present` or `positive_vs_negative`.
    """
    levels = {
        "provider": sorted({provider(r["model_id"]) for r in rows}),
        "cwe": sorted({r["cwe"] for r in rows}),
        "model_id": sorted({r["model_id"] for r in rows}),
        "prompt_id": sorted({r["prompt_id"] for r in rows}),
    }
    names = ["Intercept", target]

    # Drop first level for each categorical set.
    names += [f"provider={x}" for x in levels["provider"][1:]]
    names += [f"cwe={x}" for x in levels["cwe"][1:]]
    names += [f"{target}:provider={x}" for x in levels["provider"][1:]]
    names += [f"{target}:cwe={x}" for x in levels["cwe"][1:]]
    names += [f"model={x}" for x in levels["model_id"][1:]]
    names += [f"prompt={x}" for x in levels["prompt_id"][1:]]

    X = np.zeros((len(rows), len(names)), dtype=float)
    y = np.array([1.0 if r.get("vulnerable") else 0.0 for r in rows], dtype=float)

    for i, r in enumerate(rows):
        treatment = 0.0
        if target == "rule_present":
            treatment = 0.0 if r["condition"] == "control" else 1.0
        elif target == "positive_vs_negative":
            treatment = 1.0 if r["condition"] == "positive-framing" else 0.0
        else:
            raise ValueError(target)

        p = provider(r["model_id"])
        cwe = r["cwe"]
        model = r["model_id"]
        prompt = r["prompt_id"]

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
    try:
        cov = np.linalg.pinv(hess)
        se = np.sqrt(np.maximum(np.diag(cov), 0))
    except Exception:
        se = np.full_like(beta, float("nan"))

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
        "or_low": math.exp(coef - 1.96 * coef_se) if not math.isnan(coef_se) else float("nan"),
        "or_high": math.exp(coef + 1.96 * coef_se) if not math.isnan(coef_se) else float("nan"),
        "note": "Regularized fixed-effect logistic sensitivity model with model and prompt indicators; not a full Bayesian hierarchical model.",
    }


def headline_counts(main_rows: list[dict]) -> dict[str, Count]:
    valid = valid_rows(main_rows)
    return {
        "control": count(r for r in valid if r["condition"] == "control"),
        "negative": count(r for r in valid if r["condition"] == "negative-framing"),
        "positive": count(r for r in valid if r["condition"] == "positive-framing"),
        "any_rule": count(r for r in valid if r["condition"] in {"negative-framing", "positive-framing"}),
    }


def exploratory_tests(main_rows: list[dict]) -> list[dict]:
    valid = valid_rows(main_rows)
    tests = []
    for model in MODELS:
        for prompt in MAIN_PROMPTS:
            cell_rows = [r for r in valid if r["model_id"] == model and r["prompt_id"] == prompt]
            control = count(r for r in cell_rows if r["condition"] == "control")
            rule = count(r for r in cell_rows if r["condition"] in {"negative-framing", "positive-framing"})
            negative = count(r for r in cell_rows if r["condition"] == "negative-framing")
            positive = count(r for r in cell_rows if r["condition"] == "positive-framing")
            if control.total and rule.total:
                tests.append({
                    "family": "cell_rule_vs_control",
                    "model_id": model,
                    "prompt_id": prompt,
                    "contrast": "any_rule_vs_control",
                    "a": {"name": "any_rule", **rule.__dict__},
                    "b": {"name": "control", **control.__dict__},
                    "p": fisher(rule, control),
                })
            if negative.total and positive.total:
                tests.append({
                    "family": "cell_positive_vs_negative",
                    "model_id": model,
                    "prompt_id": prompt,
                    "contrast": "positive_vs_negative",
                    "a": {"name": "positive", **positive.__dict__},
                    "b": {"name": "negative", **negative.__dict__},
                    "p": fisher(positive, negative),
                })

    by_family: dict[str, list[int]] = defaultdict(list)
    for i, t in enumerate(tests):
        by_family[t["family"]].append(i)
    for indexes in by_family.values():
        qs = bh_fdr([tests[i]["p"] for i in indexes])
        for i, q in zip(indexes, qs):
            tests[i]["q_bh"] = q
    return tests


def control_baseline_coverage() -> dict:
    rows = load_suite("control-baselines")
    valid = valid_rows(rows)
    return {
        "valid": len(valid),
        "errors": sum(1 for r in rows if r.get("error")),
        "target_new_rows": 1440,
        "conditions": {
            condition: count(r for r in valid if r["condition"] == condition).__dict__
            for condition in ["neutral-control", "generic-security-control"]
        },
    }


def count_json(c: Count) -> dict:
    lo, hi = wilson(c.vuln, c.total)
    return {
        "vuln": c.vuln,
        "total": c.total,
        "rate": c.rate,
        "wilson_low": lo,
        "wilson_high": hi,
    }


def fmt_rate(c: Count) -> str:
    lo, hi = wilson(c.vuln, c.total)
    return f"{c.vuln}/{c.total} ({100*c.rate:.1f}%, 95% CI {100*lo:.1f}-{100*hi:.1f}%)"


def fmt_or(or_tuple: tuple[float, float, float]) -> str:
    return f"{or_tuple[0]:.3f} [{or_tuple[1]:.3f}, {or_tuple[2]:.3f}]"


def fmt_rd(rd_tuple: tuple[float, float, float]) -> str:
    return f"{100*rd_tuple[0]:.1f} pp [{100*rd_tuple[1]:.1f}, {100*rd_tuple[2]:.1f}]"


def make_markdown(report: dict) -> str:
    counts = {k: Count(v["vuln"], v["total"]) for k, v in report["headline_counts"].items()}
    lines = [
        "# Hierarchical Framing Statistics",
        "",
        "This report is a statistics companion to the existing replication summaries.",
        "It is generated by `experiments/scripts/hierarchical-framing-stats.py`.",
        "",
        "Important limitation: the logistic models below are regularized fixed-effect sensitivity models with model and prompt indicators. They are not full Bayesian hierarchical models.",
        "",
        "## Main Dataset Coverage",
        "",
        f"- Valid rows: {report['coverage']['main_valid']}",
        f"- Error rows: {report['coverage']['main_errors']}",
        "- Dataset role: confirmatory main replication.",
        "",
        "## Headline Raw Rates",
        "",
        "| Group | Vulnerable / total |",
        "| --- | ---: |",
    ]
    for key in ["control", "negative", "positive", "any_rule"]:
        lines.append(f"| {key} | {fmt_rate(counts[key])} |")

    lines += [
        "",
        "## Primary Contrasts",
        "",
        "| Contrast | Risk difference | Odds ratio | Fisher p |",
        "| --- | ---: | ---: | ---: |",
    ]
    for c in report["primary_contrasts"]:
        lines.append(
            f"| {c['contrast']} | {c['risk_difference_label']} | {c['odds_ratio_label']} | {c['fisher_p']:.3g} |"
        )

    lines += [
        "",
        "## Regularized Fixed-Effect Logistic Sensitivity Models",
        "",
        "These models include provider, CWE, treatment interactions, model indicators, and prompt indicators.",
        "",
        "| Model | N | Events | Target OR | 95% interval | p | Converged |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for m in report["fixed_effect_models"]:
        lines.append(
            f"| {m['target']} | {m['n']} | {m['events']} | {m['odds_ratio']:.3f} | "
            f"{m['or_low']:.3f}-{m['or_high']:.3f} | {m['p']:.3g} | {m['converged']} |"
        )

    lines += [
        "",
        "Interpretation:",
        "",
        "- `rule_present` estimates any targeted rule vs control in the main dataset.",
        "- `positive_vs_negative` estimates positive framing vs negative framing among rule rows only.",
        "- Because this is a regularized fixed-effect sensitivity model, use it to support claim discipline, not as a substitute for a full Bayesian hierarchical analysis.",
        "",
        "## Exploratory Per-Cell Tests With BH-FDR Correction",
        "",
        "Per-cell tests are exploratory. Use FDR-adjusted `q` values for interpretation; do not use isolated uncorrected cells as headline evidence.",
        "",
        "### Strongest Rule-vs-Control Cells",
        "",
        "| Model | Prompt | Any rule | Control | p | q |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    rule_tests = [t for t in report["exploratory_tests"] if t["family"] == "cell_rule_vs_control"]
    rule_tests.sort(key=lambda t: t["q_bh"])
    for t in rule_tests[:12]:
        lines.append(
            f"| {t['model_id']} | {t['prompt_id']} | {t['a']['vuln']}/{t['a']['total']} | "
            f"{t['b']['vuln']}/{t['b']['total']} | {t['p']:.3g} | {t['q_bh']:.3g} |"
        )

    lines += [
        "",
        "### Strongest Positive-vs-Negative Cells",
        "",
        "| Model | Prompt | Positive | Negative | p | q |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    polarity_tests = [t for t in report["exploratory_tests"] if t["family"] == "cell_positive_vs_negative"]
    polarity_tests.sort(key=lambda t: t["q_bh"])
    for t in polarity_tests[:12]:
        lines.append(
            f"| {t['model_id']} | {t['prompt_id']} | {t['a']['vuln']}/{t['a']['total']} | "
            f"{t['b']['vuln']}/{t['b']['total']} | {t['p']:.3g} | {t['q_bh']:.3g} |"
        )

    cb = report["control_baseline_coverage"]
    lines += [
        "",
        "## Control-Baseline Extension Coverage",
        "",
        f"- Valid new rows: {cb['valid']}/{cb['target_new_rows']}",
        f"- Error rows: {cb['errors']}",
        f"- Neutral control: {cb['conditions']['neutral-control']['vuln']}/{cb['conditions']['neutral-control']['total']} vulnerable",
        f"- Generic security control: {cb['conditions']['generic-security-control']['vuln']}/{cb['conditions']['generic-security-control']['total']} vulnerable",
        "",
        "This extension is too incomplete for manuscript-level claims. Current rows are checkpoint evidence only.",
        "",
        "## Claim Wording Supported Now",
        "",
        "Supported:",
        "",
        "> Rule presence substantially reduced detector-counted insecure API use in the main benchmark. Positive framing showed no consistent aggregate advantage over prohibition framing; exploratory cell-level polarity effects were heterogeneous and should be interpreted with FDR correction.",
        "",
        "Not supported without more work:",
        "",
        "- Positive and negative framing are equivalent.",
        "- Rules reliably improve real-world secure coding.",
        "- The current fast-prototyping control alone proves ordinary coding-agent improvement.",
        "- The instruction-decay incident is a general result.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    main_rows_all = load_suite("main")
    main_valid = valid_rows(main_rows_all)
    counts = headline_counts(main_rows_all)

    contrasts = []
    for name, a_key, b_key in [
        ("any_rule_minus_control", "any_rule", "control"),
        ("positive_minus_negative", "positive", "negative"),
    ]:
        a, b = counts[a_key], counts[b_key]
        contrasts.append({
            "contrast": name,
            "a": a_key,
            "b": b_key,
            "risk_difference": risk_diff_ci(a, b),
            "risk_difference_label": fmt_rd(risk_diff_ci(a, b)),
            "odds_ratio": odds_ratio(a, b),
            "odds_ratio_label": fmt_or(odds_ratio(a, b)),
            "fisher_p": fisher(a, b),
        })

    rule_rows = [r for r in main_valid if r["condition"] in {"control", "negative-framing", "positive-framing"}]
    polarity_rows = [r for r in main_valid if r["condition"] in {"negative-framing", "positive-framing"}]
    fixed_models = [
        fit_logit(rule_rows, "rule_present"),
        fit_logit(polarity_rows, "positive_vs_negative"),
    ]

    report = {
        "coverage": {
            "main_valid": len(main_valid),
            "main_errors": sum(1 for r in main_rows_all if r.get("error")),
        },
        "headline_counts": {k: count_json(v) for k, v in counts.items()},
        "primary_contrasts": contrasts,
        "fixed_effect_models": fixed_models,
        "exploratory_tests": exploratory_tests(main_rows_all),
        "control_baseline_coverage": control_baseline_coverage(),
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2))
    OUT_MD.write_text(make_markdown(report))
    print(f"Wrote {OUT_MD}")
    print(f"Wrote {OUT_JSON}")


if __name__ == "__main__":
    main()
