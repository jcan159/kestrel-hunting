from kestrel.core.models import Finding, CategoryScore, AnalysisResult
from kestrel.output.report import render_text


def _make_result(findings=None, score=None):
    return AnalysisResult(
        query="SecurityEvent | where EventID == 4624",
        environment="sentinel-scheduled",
        findings=findings or [],
        score=score or CategoryScore(),
    )


def test_render_text_contains_environment():
    result = _make_result()
    output = render_text(result, filename="test.kql")
    assert "sentinel-scheduled" in output


def test_render_text_contains_filename():
    result = _make_result()
    output = render_text(result, filename="brute-force.kql")
    assert "brute-force.kql" in output


def test_render_text_shows_overall_score():
    score = CategoryScore(correctness=80, performance=80, sentinel=80, structure=80, documentation=80)
    result = _make_result(score=score)
    output = render_text(result, filename=None)
    assert "80" in output


def test_render_text_shows_finding():
    findings = [Finding(
        rule_id="CORR002",
        category="correctness",
        severity="error",
        line=8,
        message="join without explicit kind",
        suggestion="Add kind=inner",
    )]
    result = _make_result(findings=findings)
    output = render_text(result, filename=None)
    assert "CORR002" in output
    assert "error" in output.lower() or "ERROR" in output


def test_render_text_no_findings_message():
    result = _make_result(findings=[])
    output = render_text(result, filename=None)
    assert "No findings" in output or "0" in output


def test_render_text_finding_with_no_line():
    findings = [Finding(
        rule_id="DOC001",
        category="documentation",
        severity="info",
        line=None,
        message="No MITRE tag found",
        suggestion="Add a MITRE comment",
    )]
    result = _make_result(findings=findings)
    output = render_text(result, filename=None)
    assert "DOC001" in output
