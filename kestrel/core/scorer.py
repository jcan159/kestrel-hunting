from __future__ import annotations
from kestrel.core.models import Finding, CategoryScore

_DEDUCTIONS: dict[str, int] = {"error": 20, "warning": 8, "info": 2}
_DEFAULT_WEIGHTS: dict[str, float] = {
    "correctness": 0.40,
    "performance": 0.25,
    "sentinel": 0.20,
    "structure": 0.10,
    "documentation": 0.05,
}


def score(findings: list[Finding], weight_overrides: dict[str, float] | None = None) -> CategoryScore:
    weights = {**_DEFAULT_WEIGHTS, **(weight_overrides or {})}
    totals: dict[str, int] = {cat: 100 for cat in weights}

    for finding in findings:
        cat = finding.category
        if cat in totals:
            totals[cat] = max(0, totals[cat] - _DEDUCTIONS.get(finding.severity, 0))

    overall = int(sum(totals[cat] * weights[cat] for cat in weights))
    return CategoryScore(
        correctness=totals["correctness"],
        performance=totals["performance"],
        sentinel=totals["sentinel"],
        structure=totals["structure"],
        documentation=totals["documentation"],
        _overall=overall,
    )
