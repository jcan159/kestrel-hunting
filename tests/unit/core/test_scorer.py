import pytest
from kestrel.core.models import Finding
from kestrel.core.scorer import score


def make_finding(category, severity):
    return Finding(rule_id="X", category=category, severity=severity,
                   line=1, message="", suggestion="")


def test_score_no_findings_perfect():
    s = score([])
    assert s.overall == 100
    assert s.correctness == 100


def test_score_error_deducts_20():
    s = score([make_finding("correctness", "error")])
    assert s.correctness == 80


def test_score_warning_deducts_8():
    s = score([make_finding("performance", "warning")])
    assert s.performance == 92


def test_score_info_deducts_2():
    s = score([make_finding("structure", "info")])
    assert s.structure == 98


def test_score_floored_at_zero():
    findings = [make_finding("correctness", "error")] * 10  # 10 * 20 = 200 > 100
    s = score(findings)
    assert s.correctness == 0


def test_score_different_categories_independent():
    findings = [
        make_finding("correctness", "error"),
        make_finding("performance", "warning"),
    ]
    s = score(findings)
    assert s.correctness == 80
    assert s.performance == 92
    assert s.sentinel == 100


def test_score_overall_weighted():
    # correctness=80 (40%), rest=100
    findings = [make_finding("correctness", "error")]
    s = score(findings)
    # 80*0.40 + 100*0.25 + 100*0.20 + 100*0.10 + 100*0.05 = 32+25+20+10+5 = 92
    assert s.overall == 92


def test_score_weight_overrides():
    weight_overrides = {"correctness": 1.0, "performance": 0.0,
                        "sentinel": 0.0, "structure": 0.0,
                        "documentation": 0.0}
    findings = [make_finding("correctness", "error")]
    s = score(findings, weight_overrides=weight_overrides)
    assert s.weighted_overall(weight_overrides) == 80


def test_score_weight_overrides_not_summing_to_one_raises():
    with pytest.raises(ValueError, match="weights must sum to 1.0"):
        score([], weight_overrides={"correctness": 0.5, "performance": 0.0,
                                    "sentinel": 0.0, "structure": 0.0,
                                    "documentation": 0.0})


def test_score_unknown_category_raises():
    with pytest.raises(ValueError, match="Unknown finding category"):
        score([make_finding("bogus_category", "error")])
