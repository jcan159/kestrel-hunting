# tests/unit/rules/test_correctness.py
from kestrel.core.parser import parse
from kestrel.core.rules.correctness import (
    HasSemanticMismatch,
    JoinWithoutKind,
    NondeterministicLetWithoutMaterialize,
    MissingTimeFilterInSubquery,
    DeprecatedThreatIntelTable,
    SeriesDecomposeDefaultThreshold,
    StdevWithoutZeroGuard,
    ArgMaxWithoutTimeFilter,
)
from kestrel.environments.registry import get_environment

ENV = get_environment("sentinel-scheduled")


def fires(rule, query):
    return rule.check(parse(query), ENV)


def test_corr001_has_substring_context_fires():
    # has used on a compound token where substring is needed
    q = "T | where ProcessName has 'KustoExplorer'"
    findings = fires(HasSemanticMismatch(), q)
    # This rule flags when the search term contains characters that make it likely
    # to be part of a compound token (camelCase, dots, dashes)
    assert any(f.rule_id == "CORR001" for f in findings)


def test_corr001_simple_term_no_fire():
    q = "T | where ProcessName has 'powershell'"
    findings = fires(HasSemanticMismatch(), q)
    assert findings == []


def test_corr001_powershell_no_false_positive():
    q = "T | where ProcessName has 'PowerShell'"
    findings = fires(HasSemanticMismatch(), q)
    assert findings == []


def test_corr002_join_no_kind_fires():
    q = "T1 | join T2 on Key"
    findings = fires(JoinWithoutKind(), q)
    assert any(f.rule_id == "CORR002" for f in findings)


def test_corr002_join_with_kind_no_fire():
    q = "T1 | join kind=inner T2 on Key"
    findings = fires(JoinWithoutKind(), q)
    assert findings == []


def test_corr002_join_kind_leftouter_no_fire():
    q = "T1 | join kind=leftouter (T2 | where x == 1) on Key"
    findings = fires(JoinWithoutKind(), q)
    assert findings == []


def test_corr003_nondeterministic_let_fires():
    q = ("let sample_val = SecurityEvent | sample 100;\n"
         "sample_val | summarize count() by Account\n"
         "| join (sample_val | summarize make_set(Computer) by Account) on Account")
    findings = fires(NondeterministicLetWithoutMaterialize(), q)
    assert any(f.rule_id == "CORR003" for f in findings)


def test_corr003_materialize_no_fire():
    q = ("let sample_val = materialize(SecurityEvent | sample 100);\n"
         "sample_val | summarize count() by Account\n"
         "| join (sample_val | summarize make_set(Computer) by Account) on Account")
    findings = fires(NondeterministicLetWithoutMaterialize(), q)
    assert findings == []


def test_corr004_missing_time_in_subquery_fires():
    q = ("Perf | where TimeGenerated > ago(1d)\n"
         "| join (Heartbeat | summarize max(TimeGenerated) by Computer) on Computer")
    findings = fires(MissingTimeFilterInSubquery(), q)
    assert any(f.rule_id == "CORR004" for f in findings)


def test_corr004_time_filter_in_subquery_no_fire():
    q = ("Perf | where TimeGenerated > ago(1d)\n"
         "| join (Heartbeat | where TimeGenerated > ago(1d) | summarize max(TimeGenerated) by Computer) on Computer")
    findings = fires(MissingTimeFilterInSubquery(), q)
    assert findings == []


def test_corr005_deprecated_ti_table_fires():
    q = "ThreatIntelligenceIndicator | where TimeGenerated > ago(30d) | where NetworkIP == '1.2.3.4'"
    findings = fires(DeprecatedThreatIntelTable(), q)
    assert any(f.rule_id == "CORR005" for f in findings)


def test_corr005_new_ti_table_no_fire():
    q = "ThreatIntelIndicators | where TimeGenerated > ago(30d)"
    findings = fires(DeprecatedThreatIntelTable(), q)
    assert findings == []


def test_corr006_default_threshold_fires():
    q = "T | make-series x=count() on TimeGenerated step 1h\n| extend a = series_decompose_anomalies(x)"
    findings = fires(SeriesDecomposeDefaultThreshold(), q)
    assert any(f.rule_id == "CORR006" for f in findings)


def test_corr006_explicit_threshold_no_fire():
    q = "T | make-series x=count() on TimeGenerated step 1h\n| extend a = series_decompose_anomalies(x, 3.0)"
    findings = fires(SeriesDecomposeDefaultThreshold(), q)
    assert findings == []


def test_corr006_nested_function_explicit_threshold_no_fire():
    q = ("T | make-series x=count() on TimeGenerated step 1h\n"
         "| extend a = series_decompose_anomalies(series_fill_linear(x), 3.0)")
    findings = fires(SeriesDecomposeDefaultThreshold(), q)
    assert findings == []


def test_corr007_stdev_no_zero_guard_fires():
    q = "T | extend z = (val - avg_val) / stdev_val"
    findings = fires(StdevWithoutZeroGuard(), q)
    assert any(f.rule_id == "CORR007" for f in findings)


def test_corr007_stdev_with_iff_guard_no_fire():
    q = "T | extend z = iff(stdev_val == 0, 0.0, (val - avg_val) / stdev_val)"
    findings = fires(StdevWithoutZeroGuard(), q)
    assert findings == []


def test_corr008_arg_max_without_time_fires():
    q = "T | join (OtherTable | summarize arg_max(TimeGenerated, *) by Key) on Key"
    findings = fires(ArgMaxWithoutTimeFilter(), q)
    assert any(f.rule_id == "CORR008" for f in findings)


def test_corr008_arg_max_with_time_no_fire():
    q = ("T | join (OtherTable | where TimeGenerated > ago(7d)\n"
         "| summarize arg_max(TimeGenerated, *) by Key) on Key")
    findings = fires(ArgMaxWithoutTimeFilter(), q)
    assert findings == []


def test_corr001_exe_filename_no_false_positive():
    q = "T | where ProcessName has 'cmd.exe'"
    findings = fires(HasSemanticMismatch(), q)
    assert findings == []


def test_corr001_ps1_script_no_false_positive():
    q = "T | where CommandLine has 'script.ps1'"
    findings = fires(HasSemanticMismatch(), q)
    assert findings == []


def test_corr003_dcount_no_false_positive():
    q = ("let counts = SecurityEvent | summarize dcount(Computer) by Account;\n"
         "counts | join (counts | where AccountType == 'user') on Account")
    findings = fires(NondeterministicLetWithoutMaterialize(), q)
    assert findings == []


def test_corr004_union_no_parens_no_fire():
    q = "SecurityAlert | union DeviceAlertEvents | where TimeGenerated > ago(1d)"
    findings = fires(MissingTimeFilterInSubquery(), q)
    assert findings == []


def test_corr005_in_comment_no_fire():
    q = "ThreatIntelIndicators | where TimeGenerated > ago(30d) // replaced ThreatIntelligenceIndicator"
    findings = fires(DeprecatedThreatIntelTable(), q)
    assert findings == []


def test_corr007_iif_guard_no_fire():
    q = "T | extend z = iif(stdev_val == 0, 0.0, (val - avg_val) / stdev_val)"
    findings = fires(StdevWithoutZeroGuard(), q)
    assert findings == []
