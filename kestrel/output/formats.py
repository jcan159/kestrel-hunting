from __future__ import annotations
import dataclasses
import json
from kestrel.core.models import AnalysisResult
from kestrel.output.report import render_text


def format_result(result: AnalysisResult, fmt: str, filename: str | None) -> str:
    if fmt == "text":
        return render_text(result, filename)
    if fmt == "json":
        return _to_json(result)
    if fmt == "markdown":
        return _to_markdown(result, filename)
    raise ValueError(f"Unknown format: {fmt!r}. Choose text, json, or markdown.")


def _to_json(result: AnalysisResult) -> str:
    s = result.score
    data = {
        "environment": result.environment,
        "score": {
            "overall": s.overall,
            "correctness": s.correctness,
            "performance": s.performance,
            "sentinel": s.sentinel,
            "structure": s.structure,
            "documentation": s.documentation,
        },
        "findings": [dataclasses.asdict(f) for f in result.findings],
        "rewritten_query": result.rewritten_query,
        "kql_tests": result.kql_tests,
        "logic_review": result.logic_review,
    }
    return json.dumps(data, indent=2)


def _to_markdown(result: AnalysisResult, filename: str | None) -> str:
    lines = []
    title = f"# Kestrel Analysis: {filename}" if filename else "# Kestrel Analysis"
    lines.append(title)
    lines.append("")
    lines.append(f"**Environment:** `{result.environment}`  ")
    lines.append(f"**Overall Score:** {result.score.overall}/100")
    lines.append("")
    lines.append("## Scores")
    lines.append("")
    s = result.score
    lines.append(f"| Category | Score |")
    lines.append(f"|---|---|")
    for name, val in [
        ("Correctness", s.correctness),
        ("Performance", s.performance),
        ("Sentinel", s.sentinel),
        ("Structure", s.structure),
        ("Documentation", s.documentation),
    ]:
        lines.append(f"| {name} | {val}/100 |")
    lines.append("")
    lines.append(f"## Findings ({len(result.findings)})")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
    else:
        for f in result.findings:
            loc = f"L{f.line}" if f.line is not None else "—"
            lines.append(f"**[{f.severity.upper()}] {f.rule_id}** ({loc}): {f.message}")
            lines.append(f"> {f.suggestion}")
            lines.append("")
    return "\n".join(lines)
