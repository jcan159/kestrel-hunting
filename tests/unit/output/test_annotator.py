from kestrel.core.models import Finding
from kestrel.output.annotator import annotate


def test_annotate_inserts_comment_at_correct_line():
    query = "SecurityEvent\n| where EventID == 4624\n| join T2 on Account"
    findings = [Finding("CORR002", "correctness", "error", 3, "join without kind", "Add kind=inner")]
    result = annotate(query, findings)
    result_lines = result.splitlines()
    # Comment should appear before the line with "| join"
    join_idx = next(i for i, l in enumerate(result_lines) if l.startswith("| join"))
    assert result_lines[join_idx - 1].startswith("// [ERROR CORR002]")


def test_annotate_none_line_finding_prepended():
    query = "SecurityEvent | where EventID == 4624"
    findings = [Finding("DOC001", "documentation", "info", None, "No MITRE tag", "Add tag")]
    result = annotate(query, findings)
    assert result.startswith("// [INFO DOC001]")


def test_annotate_original_lines_preserved():
    query = "SecurityEvent\n| where EventID == 4624"
    findings = []
    result = annotate(query, findings)
    assert "SecurityEvent" in result
    assert "EventID == 4624" in result


def test_annotate_multiple_findings_same_line():
    query = "T\n| where x == 1"
    findings = [
        Finding("PERF001", "performance", "warning", 2, "contains issue", "use has"),
        Finding("STR002", "structure", "info", 2, "order issue", "reorder"),
    ]
    result = annotate(query, findings)
    lines = result.splitlines()
    where_idx = next(i for i, l in enumerate(lines) if "where" in l)
    assert any("PERF001" in lines[i] for i in range(where_idx - 2, where_idx))
    assert any("STR002" in lines[i] for i in range(where_idx - 2, where_idx))
