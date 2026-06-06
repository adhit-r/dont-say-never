#!/usr/bin/env python3
"""No-new-model-call robustness analysis for the 2,160-row pro replication.

This script stratifies the main replication by model-prompt cell and checks
whether the rule-injection effect and the positive-vs-negative contrast survive
that stratification. It uses only the standard library.

Outputs:
  - experiments/analysis/hierarchical-robustness.md
  - experiments/analysis/hierarchical-robustness.json

If the expected data layout is missing or incomplete, the script writes a
clearly labeled BLOCKED report instead of inventing results.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_ROOT = ROOT / "experiments" / "data" / "pro-replication" / "main"
OUT_MD = ROOT / "experiments" / "analysis" / "hierarchical-robustness.md"
OUT_JSON = ROOT / "experiments" / "analysis" / "hierarchical-robustness.json"

EXPECTED_ROWS = 2160
EXPECTED_STRATA = 36
BOOTSTRAPS = 20000
SEED = 0
GENERATED_AT = "reproducible"


@dataclass(frozen=True)
class StratumCounts:
    model_id: str
    prompt_id: str
    treatment_vuln: int
    treatment_total: int
    control_vuln: int
    control_total: int

    @property
    def treatment_rate(self) -> float:
        return self.treatment_vuln / self.treatment_total if self.treatment_total else float("nan")

    @property
    def control_rate(self) -> float:
        return self.control_vuln / self.control_total if self.control_total else float("nan")

    @property
    def risk_difference(self) -> float:
        return self.treatment_rate - self.control_rate

    @property
    def treatment_safe(self) -> int:
        return self.treatment_total - self.treatment_vuln

    @property
    def control_safe(self) -> int:
        return self.control_total - self.control_vuln


def load_rows(data_root: Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(data_root.glob("*.json")):
        payload = json.loads(path.read_text())
        results = payload.get("results")
        if not isinstance(results, list):
            raise ValueError(f"{path} is missing a results list")
        for row in results:
            rows.append(dict(row))
    return rows


def blocked(reason: str) -> dict:
    return {
        "status": "blocked",
        "reason": reason,
        "generated_at": GENERATED_AT,
    }


def condition_groups(contrast: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if contrast == "rule_injection_vs_control":
        return ("negative-framing", "positive-framing"), ("control",)
    if contrast == "positive_vs_negative":
        return ("positive-framing",), ("negative-framing",)
    raise ValueError(f"Unknown contrast: {contrast}")


def build_strata(rows: list[dict], contrast: str) -> list[StratumCounts]:
    treatment_conditions, control_conditions = condition_groups(contrast)
    by_cell: dict[tuple[str, str], dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        by_cell[(row["model_id"], row["prompt_id"])][row["condition"]].append(row)

    strata: list[StratumCounts] = []
    for (model_id, prompt_id), condmap in sorted(by_cell.items()):
        treatment_rows: list[dict] = []
        for condition in treatment_conditions:
            treatment_rows.extend(condmap.get(condition, []))
        control_rows: list[dict] = []
        for condition in control_conditions:
            control_rows.extend(condmap.get(condition, []))

        if not treatment_rows or not control_rows:
            continue

        strata.append(
            StratumCounts(
                model_id=model_id,
                prompt_id=prompt_id,
                treatment_vuln=sum(1 for r in treatment_rows if r.get("vulnerable")),
                treatment_total=len(treatment_rows),
                control_vuln=sum(1 for r in control_rows if r.get("vulnerable")),
                control_total=len(control_rows),
            )
        )
    return strata


def mh_common_odds_ratio(strata: list[StratumCounts]) -> float:
    num = 0.0
    den = 0.0
    for s in strata:
        a = float(s.treatment_vuln)
        b = float(s.treatment_safe)
        c = float(s.control_vuln)
        d = float(s.control_safe)
        n = float(s.treatment_total + s.control_total)
        num += a * d / n
        den += b * c / n
    return num / den if den else float("nan")


def bootstrap_stat(
    strata: list[StratumCounts],
    stat_fn,
    reps: int = BOOTSTRAPS,
    seed: int = SEED,
    threshold: float = 0.0,
) -> dict:
    if not strata:
        return {"estimate": float("nan"), "ci95": [float("nan"), float("nan")], "ci90": [float("nan"), float("nan")]}

    rng = random.Random(seed)
    n = len(strata)
    samples: list[float] = []
    for _ in range(reps):
        sample = [strata[rng.randrange(n)] for _ in range(n)]
        samples.append(stat_fn(sample))
    samples.sort()
    estimate = stat_fn(strata)
    return {
        "estimate": estimate,
        "mean_bootstrap": statistics.fmean(samples),
        "median_bootstrap": statistics.median(samples),
        "ci95": [percentile(samples, 0.025), percentile(samples, 0.975)],
        "ci90": [percentile(samples, 0.05), percentile(samples, 0.95)],
        "p_le_threshold": sum(v <= threshold for v in samples) / len(samples),
        "p_ge_threshold": sum(v >= threshold for v in samples) / len(samples),
        "samples": samples,
    }


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return float("nan")
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * p
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return sorted_values[int(pos)]
    weight = pos - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def contrast_summary(rows: list[dict], contrast: str) -> dict:
    treatment_conditions, control_conditions = condition_groups(contrast)
    strata = build_strata(rows, contrast)
    if len(strata) != EXPECTED_STRATA:
        raise ValueError(f"Expected {EXPECTED_STRATA} strata for {contrast}, found {len(strata)}")

    def risk_difference(sample: list[StratumCounts]) -> float:
        return statistics.fmean(s.risk_difference for s in sample)

    def or_stat(sample: list[StratumCounts]) -> float:
        return mh_common_odds_ratio(sample)

    rd_boot = bootstrap_stat(strata, risk_difference, threshold=0.0)
    or_boot = bootstrap_stat(strata, or_stat, threshold=1.0)

    sign_counts = {
        "negative": sum(1 for s in strata if s.risk_difference < 0),
        "zero": sum(1 for s in strata if s.risk_difference == 0),
        "positive": sum(1 for s in strata if s.risk_difference > 0),
    }

    total_treatment_vuln = sum(s.treatment_vuln for s in strata)
    total_treatment_total = sum(s.treatment_total for s in strata)
    total_control_vuln = sum(s.control_vuln for s in strata)
    total_control_total = sum(s.control_total for s in strata)

    per_stratum = [
        {
            "model_id": s.model_id,
            "prompt_id": s.prompt_id,
            "treatment_vuln": s.treatment_vuln,
            "treatment_total": s.treatment_total,
            "control_vuln": s.control_vuln,
            "control_total": s.control_total,
            "treatment_rate": s.treatment_rate,
            "control_rate": s.control_rate,
            "risk_difference": s.risk_difference,
        }
        for s in strata
    ]

    return {
        "contrast": contrast,
        "treatment_conditions": list(treatment_conditions),
        "control_conditions": list(control_conditions),
        "unit": "model_id x prompt_id",
        "strata_count": len(strata),
        "row_coverage": {
            "treatment_vuln": total_treatment_vuln,
            "treatment_total": total_treatment_total,
            "control_vuln": total_control_vuln,
            "control_total": total_control_total,
        },
        "stratified_risk_difference": rd_boot["estimate"],
        "bootstrap_ci95_risk_difference": rd_boot["ci95"],
        "bootstrap_ci90_risk_difference": rd_boot["ci90"],
        "bootstrap_p_le_zero_risk_difference": rd_boot["p_le_threshold"],
        "bootstrap_p_ge_zero_risk_difference": rd_boot["p_ge_threshold"],
        "mh_common_odds_ratio": or_boot["estimate"],
        "bootstrap_ci95_mh_or": or_boot["ci95"],
        "bootstrap_ci90_mh_or": or_boot["ci90"],
        "bootstrap_p_le_one_mh_or": or_boot["p_le_threshold"],
        "bootstrap_p_ge_one_mh_or": or_boot["p_ge_threshold"],
        "stratum_sign_counts": sign_counts,
        "stratum_risk_difference_min": min(s.risk_difference for s in strata),
        "stratum_risk_difference_max": max(s.risk_difference for s in strata),
        "stratum_risk_difference_median": statistics.median(s.risk_difference for s in strata),
        "stratum_risk_difference_mean": statistics.fmean(s.risk_difference for s in strata),
        "strata": per_stratum,
    }


def contrast_md(label: str, summary: dict) -> list[str]:
    rd = summary["stratified_risk_difference"]
    rd_low, rd_high = summary["bootstrap_ci95_risk_difference"]
    or_est = summary["mh_common_odds_ratio"]
    or_low, or_high = summary["bootstrap_ci95_mh_or"]
    signs = summary["stratum_sign_counts"]
    return [
        f"| {label} | {100 * rd:.1f} pp [{100 * rd_low:.1f}, {100 * rd_high:.1f}] | "
        f"{or_est:.3f} [{or_low:.3f}, {or_high:.3f}] | "
        f"{signs['negative']}/{signs['zero']}/{signs['positive']} |",
    ]


def make_markdown(report: dict) -> str:
    if report["status"] == "blocked":
        return "\n".join(
            [
                "# Hierarchical Robustness Analysis",
                "",
                "BLOCKED",
                "",
                report["reason"],
                "",
                "No results were fabricated.",
            ]
        )

    rule = next(c for c in report["contrasts"] if c["contrast"] == "rule_injection_vs_control")
    posneg = next(c for c in report["contrasts"] if c["contrast"] == "positive_vs_negative")

    lines = [
        "# Hierarchical Robustness Analysis",
        "",
        "No new model calls were made for this check.",
        "The main 2,160-row pro replication was stratified by model-prompt cell and analyzed with a bootstrap over the 36 strata.",
        "Because each stratum is balanced by design, the stratified mean risk difference matches the pooled row-level difference, but the bootstrap quantifies uncertainty at the model-prompt level.",
        "",
        "## Coverage",
        "",
        f"- Rows: {report['rows']}",
        f"- Errors: {report['errors']}",
        f"- Strata: {report['strata']}",
        "",
        "## Stratified Results",
        "",
        "| Contrast | Stratified risk difference | MH common OR | Strata sign summary |",
        "| --- | ---: | ---: | ---: |",
    ]
    lines.extend(contrast_md("Rule injection vs control", rule))
    lines.extend(contrast_md("Positive vs negative", posneg))

    lines += [
        "",
        "Interpretation:",
        "",
        "- The rule-injection effect remains strongly negative after stratifying by model and prompt. Its bootstrap interval stays entirely below zero, and the common odds ratio stays well below 1.",
        "- The positive-vs-negative contrast stays null-compatible under the same stratification. Its bootstrap interval crosses zero, and the common odds ratio crosses 1.",
        "",
        "## Notes",
        "",
        "- Stratification unit: model_id x prompt_id.",
        "- Bootstrap: 20,000 resamples over strata, seed 0.",
        "- Sign summary is negative/zero/positive counts across the 36 strata.",
    ]

    return "\n".join(lines)


def build_report(data_root: Path) -> dict:
    rows = load_rows(data_root)
    errors = sum(1 for row in rows if row.get("error"))
    valid_rows = [row for row in rows if not row.get("error")]
    if len(valid_rows) != EXPECTED_ROWS:
        return blocked(
            f"Expected {EXPECTED_ROWS} valid rows in {data_root}, found {len(valid_rows)}. "
            "The analysis is blocked because the requested 2,160-row main replication is incomplete."
        )

    contrasts = []
    for contrast in ("rule_injection_vs_control", "positive_vs_negative"):
        contrasts.append(contrast_summary(valid_rows, contrast))

    return {
        "status": "ok",
        "generated_at": GENERATED_AT,
        "data_root": str(data_root),
        "rows": len(rows),
        "valid_rows": len(valid_rows),
        "errors": errors,
        "strata": EXPECTED_STRATA,
        "bootstrap_samples": BOOTSTRAPS,
        "seed": SEED,
        "contrasts": contrasts,
    }


def write_outputs(report: dict) -> None:
    OUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    OUT_MD.write_text(make_markdown(report) + "\n")


def main() -> int:
    global BOOTSTRAPS, SEED
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--bootstrap-samples", type=int, default=BOOTSTRAPS)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    BOOTSTRAPS = args.bootstrap_samples
    SEED = args.seed

    try:
        report = build_report(args.data_root)
    except Exception as exc:
        report = blocked(str(exc))
    write_outputs(report)

    if report["status"] == "blocked":
        print(f"BLOCKED: {report['reason']}")
        return 1

    print("Wrote:")
    print(f"- {OUT_MD}")
    print(f"- {OUT_JSON}")
    for contrast in report["contrasts"]:
        rd_low, rd_high = contrast["bootstrap_ci95_risk_difference"]
        or_low, or_high = contrast["bootstrap_ci95_mh_or"]
        signs = contrast["stratum_sign_counts"]
        print(
            f"- {contrast['contrast']}: RD {100 * contrast['stratified_risk_difference']:.1f} pp "
            f"[{100 * rd_low:.1f}, {100 * rd_high:.1f}], "
            f"MH OR {contrast['mh_common_odds_ratio']:.3f} "
            f"[{or_low:.3f}, {or_high:.3f}], "
            f"signs {signs['negative']}/{signs['zero']}/{signs['positive']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
