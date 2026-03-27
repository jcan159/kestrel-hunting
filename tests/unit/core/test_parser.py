from kestrel.core.parser import parse, ParsedQuery, PipelineStage, LetBinding

SIMPLE_QUERY = """\
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| project TimeGenerated, Account, Computer
"""

LET_QUERY = """\
let threshold = 10;
let base = SecurityEvent | where EventID == 4624;
base
| summarize count() by Account
| where count_ > threshold
"""

COMMENT_QUERY = """\
// MITRE ATT&CK: T1110
// Author: SOC Team
SecurityEvent
| where TimeGenerated > ago(1d) // time filter
| where EventID == 4625
"""


def test_parse_returns_parsed_query():
    result = parse(SIMPLE_QUERY)
    assert isinstance(result, ParsedQuery)


def test_parse_char_count():
    result = parse(SIMPLE_QUERY)
    assert result.char_count == len(SIMPLE_QUERY)


def test_parse_table_name():
    result = parse(SIMPLE_QUERY)
    assert result.table == "SecurityEvent"


def test_parse_pipeline_stages():
    result = parse(SIMPLE_QUERY)
    operators = [s.operator for s in result.pipeline]
    assert operators == ["where", "where", "project"]


def test_parse_pipeline_line_numbers():
    result = parse(SIMPLE_QUERY)
    assert result.pipeline[0].line == 2
    assert result.pipeline[1].line == 3
    assert result.pipeline[2].line == 4


def test_parse_pipeline_args():
    result = parse(SIMPLE_QUERY)
    assert "TimeGenerated" in result.pipeline[0].args
    assert "EventID == 4624" in result.pipeline[1].args


def test_parse_let_bindings():
    result = parse(LET_QUERY)
    names = [b.name for b in result.lets]
    assert "threshold" in names
    assert "base" in names


def test_parse_let_usage_count():
    result = parse(LET_QUERY)
    base_binding = next(b for b in result.lets if b.name == "base")
    threshold_binding = next(b for b in result.lets if b.name == "threshold")
    assert base_binding.usage_count >= 1
    assert threshold_binding.usage_count >= 1


def test_parse_let_tabular():
    result = parse(LET_QUERY)
    base_binding = next(b for b in result.lets if b.name == "base")
    threshold_binding = next(b for b in result.lets if b.name == "threshold")
    assert base_binding.is_tabular is True
    assert threshold_binding.is_tabular is False


def test_parse_strips_inline_comments():
    result = parse(COMMENT_QUERY)
    # The where clause line has an inline comment — args should not include it
    time_stage = result.pipeline[0]
    assert "//" not in time_stage.args


def test_parse_detects_header_comments():
    result = parse(COMMENT_QUERY)
    assert any("MITRE" in c for c in result.comments)


def test_parse_lines():
    result = parse(SIMPLE_QUERY)
    assert result.lines[0] == "SecurityEvent"
