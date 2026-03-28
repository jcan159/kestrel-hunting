# tests/unit/rules/test_performance.py
import pytest
from kestrel.core.parser import parse
from kestrel.core.rules.performance import (
    ContainsInsteadOfHas,
    RegexWithoutPrefilter,
    SearchOrUnionStarPerf,
    FilterOnComputedColumn,
    NoEarlyProject,
    LetWithoutMaterialize,
    DuplicateTableScan,
    JoinWithoutHint,
    GraphMatchDeepPath,
    DcountWithoutToscalar,
    SerializeEarly,
    CaseInsensitiveOperator,
)
from kestrel.environments.registry import get_environment

ENV = get_environment("sentinel-scheduled")


def fires(rule, query):
    return rule.check(parse(query), ENV)


def test_perf001_contains_fires():
    findings = fires(ContainsInsteadOfHas(), "T | where CommandLine contains 'powershell'")
    assert any(f.rule_id == "PERF001" for f in findings)


def test_perf001_has_no_fire():
    findings = fires(ContainsInsteadOfHas(), "T | where CommandLine has 'powershell'")
    assert findings == []


def test_perf002_regex_without_prefilter_fires():
    findings = fires(RegexWithoutPrefilter(), "T | where Name matches regex @'.*evil.*'")
    assert any(f.rule_id == "PERF002" for f in findings)


def test_perf002_regex_with_has_no_fire():
    findings = fires(RegexWithoutPrefilter(),
                     "T | where Name has 'evil'\n| where Name matches regex @'^evil.*'")
    assert findings == []


def test_perf003_search_star_fires():
    findings = fires(SearchOrUnionStarPerf(), "search *")
    assert any(f.rule_id == "PERF003" for f in findings)


def test_perf003_union_star_fires():
    findings = fires(SearchOrUnionStarPerf(), "T | union * | where x == 1")
    assert any(f.rule_id == "PERF003" for f in findings)


def test_perf003_specific_table_no_fire():
    findings = fires(SearchOrUnionStarPerf(), "SecurityEvent | where EventID == 1")
    assert findings == []


def test_perf004_filter_on_computed_fires():
    q = "T | extend Msg = strcat('a', Col)\n| where Msg has 'error'"
    findings = fires(FilterOnComputedColumn(), q)
    assert any(f.rule_id == "PERF004" for f in findings)


def test_perf004_filter_on_raw_column_no_fire():
    findings = fires(FilterOnComputedColumn(), "T | where Col has 'error'")
    assert findings == []


def test_perf005_no_early_project_fires():
    q = ("SecurityEvent\n| where TimeGenerated > ago(1d)\n"
         "| join kind=inner OtherTable on Account\n| summarize count() by Account")
    findings = fires(NoEarlyProject(), q)
    assert any(f.rule_id == "PERF005" for f in findings)


def test_perf005_project_before_join_no_fire():
    q = ("SecurityEvent\n| where TimeGenerated > ago(1d)\n"
         "| project Account, TimeGenerated\n| join kind=inner OtherTable on Account")
    findings = fires(NoEarlyProject(), q)
    assert findings == []


def test_perf006_let_without_materialize_fires():
    q = ("let base = SecurityEvent | where EventID == 4624;\n"
         "base\n| summarize count() by Account\n"
         "| join (base | summarize make_set(Computer) by Account) on Account")
    findings = fires(LetWithoutMaterialize(), q)
    assert any(f.rule_id == "PERF006" for f in findings)


def test_perf006_single_use_no_fire():
    q = ("let base = SecurityEvent | where EventID == 4624;\n"
         "base | summarize count() by Account")
    findings = fires(LetWithoutMaterialize(), q)
    assert findings == []


def test_perf006_materialize_no_fire():
    q = ("let base = materialize(SecurityEvent | where EventID == 4624);\n"
         "base\n| summarize count() by Account\n"
         "| join (base | summarize make_set(Computer) by Account) on Account")
    findings = fires(LetWithoutMaterialize(), q)
    assert findings == []


def test_perf007_duplicate_scan_fires():
    q = ("SecurityEvent | where EventID == 4624 | summarize count() by Account\n"
         "| join (SecurityEvent | where EventID == 4688 | summarize count() by Account) on Account")
    findings = fires(DuplicateTableScan(), q)
    assert any(f.rule_id == "PERF007" for f in findings)


def test_perf007_single_scan_no_fire():
    findings = fires(DuplicateTableScan(), "SecurityEvent | where EventID == 1 | summarize count() by Account")
    assert findings == []


def test_perf008_join_without_hint_fires():
    q = "T1\n| where x == 1\n| join kind=inner T2 on Key"
    findings = fires(JoinWithoutHint(), q)
    assert any(f.rule_id == "PERF008" for f in findings)


def test_perf008_join_with_hint_no_fire():
    q = "T1\n| where x == 1\n| join hint.strategy=broadcast kind=inner T2 on Key"
    findings = fires(JoinWithoutHint(), q)
    assert findings == []


def test_perf009_graph_deep_path_fires():
    q = "edges | make-graph src --> dst with nodes on id\n| graph-match (a)-[p*1..6]->(b)"
    findings = fires(GraphMatchDeepPath(), q)
    assert any(f.rule_id == "PERF009" for f in findings)


def test_perf009_shallow_path_no_fire():
    q = "edges | make-graph src --> dst with nodes on id\n| graph-match (a)-[p*1..4]->(b)"
    findings = fires(GraphMatchDeepPath(), q)
    assert findings == []


def test_perf010_dcount_without_toscalar_fires():
    q = ("let total = SecurityEvent | summarize dcount(Computer);\n"
         "SecurityEvent\n| where Computer != ''\n| join (SecurityEvent | summarize dcount(Computer)) on Computer")
    findings = fires(DcountWithoutToscalar(), q)
    assert any(f.rule_id == "PERF010" for f in findings)


def test_perf011_serialize_early_fires():
    q = "T | serialize | where x == 1 | summarize count() by y"
    findings = fires(SerializeEarly(), q)
    assert any(f.rule_id == "PERF011" for f in findings)


def test_perf011_serialize_late_no_fire():
    q = "T | where x == 1 | summarize count() by y | serialize | extend r = row_number()"
    findings = fires(SerializeEarly(), q)
    assert findings == []


def test_perf012_case_insensitive_fires():
    findings = fires(CaseInsensitiveOperator(), "T | where Name =~ 'admin'")
    assert any(f.rule_id == "PERF012" for f in findings)


def test_perf012_case_sensitive_no_fire():
    findings = fires(CaseInsensitiveOperator(), "T | where Name == 'admin'")
    assert findings == []
