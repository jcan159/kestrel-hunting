from __future__ import annotations
from kestrel.core.models import AnalysisResult, Finding

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}
_BAR_WIDTH = 14


def _bar(score: int) -> str:
    filled = round(score / 100 * _BAR_WIDTH)
    return "█" * filled + "░" * (_BAR_WIDTH - filled)


def render_text(result: AnalysisResult, filename: str | None) -> str:
    lines = []
    lines.append("Kestrel Analysis Report")
    lines.append("═" * 43)

    meta = []
    if filename:
        meta.append(f"File:        {filename}")
    meta.append(f"Environment: {result.environment}")
    meta.append(f"Overall Score: {result.score.overall}/100")
    lines.extend(meta)
    lines.append("")

    s = result.score
    for name, val in [
        ("Correctness  ", s.correctness),
        ("Performance  ", s.performance),
        ("Sentinel     ", s.sentinel),
        ("Structure    ", s.structure),
        ("Documentation", s.documentation),
    ]:
        lines.append(f"  {name} {val:3d}/100  {_bar(val)}")

    lines.append("")
    lines.append(f"Findings ({len(result.findings)})")
    lines.append("─" * 43)

    if not result.findings:
        lines.append("No findings.")
    else:
        sorted_findings = sorted(result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
        for f in sorted_findings:
            loc = f"L{f.line}" if f.line is not None else "—"
            lines.append(
                f"[{f.severity.upper():<7}] {f.rule_id:<8} {loc:<5} {f.message}"
            )
            lines.append(f"{'':>23} {f.suggestion}")
            lines.append("")

    return "\n".join(lines)
