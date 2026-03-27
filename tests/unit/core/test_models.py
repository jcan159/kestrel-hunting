from kestrel.core.models import Finding, CategoryScore, AnalysisResult


def test_finding_fields():
    f = Finding(
        rule_id="PERF001",
        category="performance",
        severity="warning",
        line=3,
        message="contains used",
        suggestion="use has instead",
    )
    assert f.rule_id == "PERF001"
    assert f.line == 3


def test_finding_line_optional():
    f = Finding(
        rule_id="DOC001",
        category="documentation",
        severity="info",
        line=None,
        message="missing MITRE tag",
        suggestion="add // MITRE ATT&CK: T1110",
    )
    assert f.line is None


def test_category_score_defaults_to_100():
    s = CategoryScore()
    assert s.correctness == 100
    assert s.performance == 100
    assert s.sentinel == 100
    assert s.structure == 100
    assert s.documentation == 100


def test_category_score_overall_weighted():
    s = CategoryScore(
        correctness=100,
        performance=100,
        sentinel=100,
        structure=100,
        documentation=100,
    )
    assert s.overall == 100


def test_category_score_overall_partial():
    # correctness=0 (40%), rest=100
    s = CategoryScore(correctness=0, performance=100, sentinel=100, structure=100, documentation=100)
    # 0*0.40 + 100*0.25 + 100*0.20 + 100*0.10 + 100*0.05 = 60
    assert s.overall == 60


def test_analysis_result_defaults():
    r = AnalysisResult(query="SecurityEvent | where EventID == 4624", environment="sentinel-scheduled")
    assert r.findings == []
    assert r.rewritten_query is None
    assert r.kql_tests is None
    assert r.logic_review is None
