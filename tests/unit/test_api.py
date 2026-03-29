import pytest
from unittest.mock import patch
from kestrel import analyze, AnalysisConfig
from kestrel.core.models import AnalysisResult


def test_analyze_returns_analysis_result():
    cfg = AnalysisConfig(environment="sentinel-scheduled", llm_enabled=False)
    result = analyze("SecurityEvent | where EventID == 4624", cfg)
    assert isinstance(result, AnalysisResult)


def test_analyze_environment_in_result():
    cfg = AnalysisConfig(environment="sentinel-scheduled", llm_enabled=False)
    result = analyze("T | where x == 1", cfg)
    assert result.environment == "sentinel-scheduled"


def test_analyze_score_between_0_and_100():
    cfg = AnalysisConfig(environment="sentinel-scheduled", llm_enabled=False)
    result = analyze("T | where x == 1", cfg)
    assert 0 <= result.score.overall <= 100


def test_analyze_bad_query_produces_findings():
    cfg = AnalysisConfig(environment="sentinel-scheduled", llm_enabled=False)
    result = analyze("SecurityEvent | where EventID == 4624 | join T2 on Account", cfg)
    rule_ids = {f.rule_id for f in result.findings}
    assert "CORR002" in rule_ids


def test_analyze_disabled_rule_not_in_findings():
    cfg = AnalysisConfig(
        environment="sentinel-scheduled",
        llm_enabled=False,
        disabled_rule_ids={"CORR002"},
    )
    result = analyze("T1 | join T2 on Key", cfg)
    assert not any(f.rule_id == "CORR002" for f in result.findings)


def test_analyze_with_llm_calls_all_three(monkeypatch):
    with patch("kestrel.api.generate_logic_review", return_value="logic") as lr, \
         patch("kestrel.api.generate_kql_tests", return_value="tests") as tg, \
         patch("kestrel.api.generate_rewrite", return_value="rewrite") as rw:
        cfg = AnalysisConfig(
            environment="sentinel-scheduled",
            llm_enabled=True,
            outputs=["report", "logic_review", "tests", "rewrite"],
        )
        result = analyze("T | where x == 1", cfg)
    assert lr.called
    assert tg.called
    assert rw.called
    assert result.logic_review == "logic"
    assert result.kql_tests == "tests"
    assert result.rewritten_query == "rewrite"


def test_analyze_no_llm_output_is_none():
    cfg = AnalysisConfig(environment="sentinel-scheduled", llm_enabled=False)
    result = analyze("T | where x == 1", cfg)
    assert result.logic_review is None
    assert result.kql_tests is None
    assert result.rewritten_query is None


def test_analysis_config_defaults():
    cfg = AnalysisConfig()
    assert cfg.environment == "sentinel-scheduled"
    assert cfg.llm_enabled is True
    assert cfg.outputs == ["report"]
    assert cfg.disabled_rule_ids == set()
    assert cfg.severity_overrides == {}
