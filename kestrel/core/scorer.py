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
    if weight_overrides:
        weights = {**_DEFAULT_WEIGHTS, **weight_overrides}
        total = sum(weights.values())
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"weights must sum to 1.0, got {total}")
    else:
        weights = _DEFAULT_WEIGHTS

    totals: dict[str, int] = {cat: 100 for cat in _DEFAULT_WEIGHTS}

    for finding in findings:
        cat = finding.category
        if cat not in totals:
            raise ValueError(f"Unknown finding category: {cat!r}")
        totals[cat] = max(0, totals[cat] - _DEDUCTIONS.get(finding.severity, 0))

    return CategoryScore(
        correctness=totals["correctness"],
        performance=totals["performance"],
        sentinel=totals["sentinel"],
        structure=totals["structure"],
        documentation=totals["documentation"],
    )
