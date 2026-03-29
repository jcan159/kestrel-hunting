from __future__ import annotations
from collections import defaultdict
from kestrel.core.models import Finding


def annotate(query: str, findings: list[Finding]) -> str:
    """Return the query with // [SEVERITY RULE_ID] comments injected before the relevant lines."""
    original_lines = query.splitlines()

    # Group findings by line number; None-line findings go to a special bucket
    by_line: dict[int | None, list[Finding]] = defaultdict(list)
    for f in findings:
        by_line[f.line].append(f)

    result: list[str] = []

    # Prepend None-line comments at the top
    for f in by_line.get(None, []):
        result.append(f"// [{f.severity.upper()} {f.rule_id}] {f.message}")

    for i, line in enumerate(original_lines, start=1):
        for f in by_line.get(i, []):
            result.append(f"// [{f.severity.upper()} {f.rule_id}] {f.message}")
        result.append(line)

    return "\n".join(result)
