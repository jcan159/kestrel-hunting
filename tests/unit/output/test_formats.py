import json
import pytest
from kestrel.core.models import Finding, CategoryScore, AnalysisResult
from kestrel.output.formats import format_result


def _make_result(findings=None):
    return AnalysisResult(
        query="SecurityEvent | where EventID == 4624",
        environment="sentinel-scheduled",
        findings=findings or [
            Finding(
                rule_id="CORR002",
                category="correctness",
                severity="error",
                line=3,
                message="join without kind",
                suggestion="Add kind=inner",
            )
        ],
        score=CategoryScore(correctness=72),
    )


def test_format_result_json_is_valid():
    output = format_result(_make_result(), fmt="json", filename="r.kql")
    data = json.loads(output)
    assert data["environment"] == "sentinel-scheduled"
    assert data["score"]["overall"] == _make_result().score.overall
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "CORR002"


def test_format_result_json_none_line_is_null():
    result = _make_result(findings=[
        Finding("DOC001", "documentation", "info", None, "no tag", "add tag")
    ])
    data = json.loads(format_result(result, fmt="json", filename=None))
    assert data["findings"][0]["line"] is None


def test_format_result_markdown_contains_heading():
    output = format_result(_make_result(), fmt="markdown", filename="r.kql")
    assert "# Kestrel" in output or "## Kestrel" in output


def test_format_result_markdown_contains_finding():
    output = format_result(_make_result(), fmt="markdown", filename=None)
    assert "CORR002" in output


def test_format_result_text_contains_score():
    output = format_result(_make_result(), fmt="text", filename=None)
    assert "/100" in output


def test_format_result_raises_on_unknown_format():
    with pytest.raises(ValueError, match="Unknown format"):
        format_result(_make_result(), fmt="xml", filename=None)
