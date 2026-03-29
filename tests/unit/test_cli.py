import json
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from kestrel.cli import main
from kestrel.core.models import AnalysisResult, CategoryScore, Finding


def _mock_result(findings=None, score=None):
    return AnalysisResult(
        query="T | where x == 1",
        environment="sentinel-scheduled",
        findings=findings or [],
        score=score or CategoryScore(),
    )


def test_analyze_no_args_shows_help():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", "--help"])
    assert result.exit_code == 0
    assert "--env" in result.output


def test_analyze_file_exit_0_no_findings(tmp_path):
    kql = tmp_path / "rule.kql"
    kql.write_text("T | where x == 1")
    with patch("kestrel.cli.analyze", return_value=_mock_result()) as mock_analyze:
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(kql), "--env", "sentinel-scheduled", "--no-llm"])
    assert result.exit_code == 0


def test_analyze_exit_1_on_error_finding(tmp_path):
    kql = tmp_path / "rule.kql"
    kql.write_text("T | where x == 1")
    error_finding = Finding("CORR002", "correctness", "error", 1, "msg", "fix")
    with patch("kestrel.cli.analyze", return_value=_mock_result(findings=[error_finding])):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(kql), "--no-llm"])
    assert result.exit_code == 1


def test_analyze_exit_0_on_warning_by_default(tmp_path):
    kql = tmp_path / "rule.kql"
    kql.write_text("T | where x == 1")
    warn_finding = Finding("PERF001", "performance", "warning", 1, "msg", "fix")
    with patch("kestrel.cli.analyze", return_value=_mock_result(findings=[warn_finding])):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(kql), "--no-llm"])
    assert result.exit_code == 0


def test_analyze_json_format_output(tmp_path):
    kql = tmp_path / "rule.kql"
    kql.write_text("T | where x == 1")
    with patch("kestrel.cli.analyze", return_value=_mock_result()):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(kql), "--format", "json", "--no-llm"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "findings" in data
    assert "score" in data


def test_analyze_stdin(tmp_path):
    with patch("kestrel.cli.analyze", return_value=_mock_result()):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "-", "--no-llm"], input="T | where x == 1")
    assert result.exit_code == 0


def test_analyze_min_score_fail(tmp_path):
    kql = tmp_path / "rule.kql"
    kql.write_text("T | where x == 1")
    low_score = CategoryScore(correctness=40, performance=40, sentinel=40, structure=40, documentation=40)
    with patch("kestrel.cli.analyze", return_value=_mock_result(score=low_score)):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(kql), "--min-score", "80", "--no-llm"])
    assert result.exit_code == 1


def test_analyze_exit_3_on_exception(tmp_path):
    kql = tmp_path / "rule.kql"
    kql.write_text("T | where x == 1")
    with patch("kestrel.cli.analyze", side_effect=Exception("API error")):
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", str(kql), "--no-llm"])
    assert result.exit_code == 3
