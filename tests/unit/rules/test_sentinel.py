# tests/unit/rules/test_sentinel.py
from kestrel.core.parser import parse
from kestrel.core.rules.sentinel import (
    SearchOrUnionStar,
    QueryTooLong,
    AdxCrossClusterFunction,
    BagUnpackWithoutColumnIfExists,
    TimeGeneratedNotInOutput,
    RawTableInsteadOfAsim,
    NrtTopLevelTimeFilter,
    ContinuousJoinOrUnion,
    ContinuousUnsupportedOperator,
    MissingEntityIdentifier,
    TimestampFilteredInXdr,
)
from kestrel.environments.registry import get_environment

SCHED = get_environment("sentinel-scheduled")
NRT = get_environment("sentinel-nrt")
XDR = get_environment("defender-xdr")
XDR_CONT = get_environment("defender-xdr-continuous")


def fires(rule, query, env=SCHED):
    return rule.check(parse(query), env)


def test_sent001_search_star_fires():
    assert any(f.rule_id == "SENT001" for f in fires(SearchOrUnionStar(), "search *"))


def test_sent001_union_star_fires():
    assert any(f.rule_id == "SENT001" for f in fires(SearchOrUnionStar(), "T | union *"))


def test_sent001_union_kind_outer_star_fires():
    assert any(f.rule_id == "SENT001" for f in fires(SearchOrUnionStar(), "T | union kind=outer *"))


def test_sent001_union_kind_inner_star_fires():
    assert any(f.rule_id == "SENT001" for f in fires(SearchOrUnionStar(), "T | union kind=inner *"))


def test_sent001_specific_table_no_fire():
    assert fires(SearchOrUnionStar(), "SecurityEvent | where EventID == 1") == []


def test_sent002_long_query_fires():
    long_q = "SecurityEvent\n| where " + " or ".join([f"EventID == {i}" for i in range(600)])
    assert any(f.rule_id == "SENT002" for f in fires(QueryTooLong(), long_q))


def test_sent002_short_query_no_fire():
    assert fires(QueryTooLong(), "SecurityEvent | where EventID == 1") == []


def test_sent003_adx_function_fires():
    q = "cluster('mycluster').database('mydb').MyTable | where x == 1"
    assert any(f.rule_id == "SENT003" for f in fires(AdxCrossClusterFunction(), q))


def test_sent003_local_table_no_fire():
    assert fires(AdxCrossClusterFunction(), "SecurityEvent | where EventID == 1") == []


def test_sent004_bag_unpack_no_guard_fires():
    q = "T | evaluate bag_unpack(Properties)\n| project field1"
    assert any(f.rule_id == "SENT004" for f in fires(BagUnpackWithoutColumnIfExists(), q))


def test_sent004_bag_unpack_with_guard_no_fire():
    q = "T | evaluate bag_unpack(Properties)\n| project field1 = column_ifexists('field1', '')"
    assert fires(BagUnpackWithoutColumnIfExists(), q) == []


def test_sent005_no_timegenerated_in_output_fires():
    q = "SecurityEvent | where EventID == 1 | project Account, Computer"
    assert any(f.rule_id == "SENT005" for f in fires(TimeGeneratedNotInOutput(), q))


def test_sent005_timegenerated_in_output_no_fire():
    q = "SecurityEvent | where EventID == 1 | project TimeGenerated, Account"
    assert fires(TimeGeneratedNotInOutput(), q) == []


def test_sent005_no_project_no_fire():
    # No project means all columns returned, including TimeGenerated
    q = "SecurityEvent | where EventID == 1"
    assert fires(TimeGeneratedNotInOutput(), q) == []


def test_sent005_project_rename_timegenerated_no_fire():
    q = "SecurityEvent | where EventID == 1 | project Account, OriginalTime | project-rename TimeGenerated = OriginalTime"
    assert fires(TimeGeneratedNotInOutput(), q) == []


def test_sent006_raw_dns_table_fires():
    q = "DnsEvents | where TimeGenerated > ago(1d) | where ResponseCode == 'NXDOMAIN'"
    assert any(f.rule_id == "SENT006" for f in fires(RawTableInsteadOfAsim(), q))


def test_sent006_asim_parser_no_fire():
    q = "_Im_Dns(responsecodename='NXDOMAIN') | summarize count() by SrcIpAddr"
    assert fires(RawTableInsteadOfAsim(), q) == []


def test_sent007_nrt_top_level_time_filter_fires():
    q = "SecurityEvent | where TimeGenerated > ago(5m) | where EventID == 1"
    assert any(f.rule_id == "SENT007" for f in fires(NrtTopLevelTimeFilter(), q, NRT))


def test_sent007_no_fire_for_scheduled():
    q = "SecurityEvent | where TimeGenerated > ago(5m) | where EventID == 1"
    # SENT007 is disabled for sentinel-scheduled
    assert NRT.is_rule_disabled("SENT007") is False
    assert SCHED.is_rule_disabled("SENT007") is True


def test_sent008_continuous_join_fires():
    q = "DeviceEvents | join kind=inner DeviceInfo on DeviceId"
    assert any(f.rule_id == "SENT008" for f in fires(ContinuousJoinOrUnion(), q, XDR_CONT))


def test_sent008_no_join_no_fire():
    q = "DeviceEvents | where ActionType == 'ProcessCreated' | project Timestamp, DeviceId"
    assert fires(ContinuousJoinOrUnion(), q, XDR_CONT) == []


def test_sent009_unsupported_operator_fires():
    # make-series is not supported in Continuous mode
    q = "DeviceEvents | where ActionType == 'ProcessCreated' | make-series count() on Timestamp step 1h"
    assert any(f.rule_id == "SENT009" for f in fires(ContinuousUnsupportedOperator(), q, XDR_CONT))


def test_sent009_supported_operator_no_fire():
    q = "DeviceEvents | where ActionType == 'ProcessCreated' | project Timestamp, DeviceId, ReportId"
    assert fires(ContinuousUnsupportedOperator(), q, XDR_CONT) == []


def test_sent010_missing_entity_identifier_fires():
    q = "DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, ReportId, FileName"
    assert any(f.rule_id == "SENT010" for f in fires(MissingEntityIdentifier(), q, XDR))


def test_sent010_has_device_id_no_fire():
    q = "DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId, ReportId"
    assert fires(MissingEntityIdentifier(), q, XDR) == []


def test_sent010_project_keep_without_entity_fires():
    q = "DeviceProcessEvents | where Timestamp > ago(1h) | project-keep Timestamp, ReportId, FileName"
    assert any(f.rule_id == "SENT010" for f in fires(MissingEntityIdentifier(), q, XDR))


def test_sent010_project_keep_with_entity_no_fire():
    q = "DeviceProcessEvents | where Timestamp > ago(1h) | project-keep Timestamp, DeviceId, ReportId"
    assert fires(MissingEntityIdentifier(), q, XDR) == []


def test_sent011_timestamp_filtered_fires():
    q = "DeviceEvents | where Timestamp > ago(1h) | where ActionType == 'x'"
    assert any(f.rule_id == "SENT011" for f in fires(TimestampFilteredInXdr(), q, XDR))


def test_sent011_no_timestamp_filter_no_fire():
    q = "DeviceEvents | where ActionType == 'ProcessCreated'"
    assert fires(TimestampFilteredInXdr(), q, XDR) == []
