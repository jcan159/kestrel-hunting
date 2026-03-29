# tests/unit/rules/test_structure.py
from kestrel.core.parser import parse
from kestrel.core.rules.structure import (
    TimeFilterNotFirst,
    WhereNotOrderedBySelectivity,
    NoProjectBeforeJoin,
    HardcodedLiterals,
    PipelineOrderDeviation,
)
from kestrel.environments.registry import get_environment

ENV = get_environment("sentinel-scheduled")


def fires(rule, query):
    return rule.check(parse(query), ENV)


def test_str001_time_filter_not_first_fires():
    q = "SecurityEvent\n| where EventID == 4624\n| where TimeGenerated > ago(1d)"
    assert any(f.rule_id == "STR001" for f in fires(TimeFilterNotFirst(), q))


def test_str001_time_filter_first_no_fire():
    q = "SecurityEvent\n| where TimeGenerated > ago(1d)\n| where EventID == 4624"
    assert fires(TimeFilterNotFirst(), q) == []


def test_str001_no_where_no_fire():
    q = "SecurityEvent | summarize count() by EventID"
    assert fires(TimeFilterNotFirst(), q) == []


def test_str002_expensive_before_cheap_fires():
    q = "T | where Col matches regex @'.*evil.*'\n| where TimeGenerated > ago(1d)"
    assert any(f.rule_id == "STR002" for f in fires(WhereNotOrderedBySelectivity(), q))


def test_str002_cheap_before_expensive_no_fire():
    q = "T | where TimeGenerated > ago(1d)\n| where Col matches regex @'.*evil.*'"
    assert fires(WhereNotOrderedBySelectivity(), q) == []


def test_str003_no_project_before_join_fires():
    q = "T1\n| where x == 1\n| join kind=inner T2 on Key\n| summarize count() by Key"
    assert any(f.rule_id == "STR003" for f in fires(NoProjectBeforeJoin(), q))


def test_str003_project_before_join_no_fire():
    q = "T1\n| where x == 1\n| project Key, Val\n| join kind=inner T2 on Key"
    assert fires(NoProjectBeforeJoin(), q) == []


def test_str004_hardcoded_number_fires():
    q = "SecurityEvent\n| where TimeGenerated > ago(1d)\n| where FailCount > 10"
    assert any(f.rule_id == "STR004" for f in fires(HardcodedLiterals(), q))


def test_str004_let_variable_no_fire():
    q = "let threshold = 10;\nSecurityEvent\n| where TimeGenerated > ago(1d)\n| where FailCount > threshold"
    assert fires(HardcodedLiterals(), q) == []


def test_str004_ago_hardcoded_fires():
    q = "SecurityEvent | where TimeGenerated > ago(1d) | summarize count() by Account"
    assert any(f.rule_id == "STR004" for f in fires(HardcodedLiterals(), q))


def test_str005_summarize_before_join_fires():
    q = "T1 | summarize count() by Key | join kind=inner T2 on Key | where x == 1"
    assert any(f.rule_id == "STR005" for f in fires(PipelineOrderDeviation(), q))


def test_str005_canonical_order_no_fire():
    q = "T1 | where x == 1 | project Key | join kind=inner T2 on Key | summarize count() by Key"
    assert fires(PipelineOrderDeviation(), q) == []
