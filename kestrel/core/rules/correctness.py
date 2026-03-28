from __future__ import annotations
import re
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.core.rules import Rule
from kestrel.environments.registry import Environment

_JOIN_KIND_RE = re.compile(r"\bkind\s*=", re.IGNORECASE)
# sample in KQL is used as "| sample N" (no parens) OR rand/dcount with parens
_NONDETERMINISTIC_RE = re.compile(r"\b(rand\s*\(|dcount\s*\(|\bsample\b)", re.IGNORECASE)
_MATERIALIZE_RE = re.compile(r"\bmaterialize\s*\(", re.IGNORECASE)
_SERIES_DECOMPOSE_START_RE = re.compile(r"\bseries_decompose_anomalies\s*\(", re.IGNORECASE)
_STDEV_DIV_RE = re.compile(r"/\s*stdev", re.IGNORECASE)
_IFF_STDEV_RE = re.compile(r"\biff\s*\([^,]*stdev[^,]*==\s*0", re.IGNORECASE)
_ARG_MAX_RE = re.compile(r"\barg_max\s*\(TimeGenerated", re.IGNORECASE)
# Time filter: requires a where/filter clause with TimeGenerated, not just any mention
_WHERE_TIME_FILTER_RE = re.compile(r"\bwhere\b[^|]*\b(TimeGenerated|Timestamp)\b", re.IGNORECASE)
_TIME_FILTER_RE = re.compile(r"\b(TimeGenerated|Timestamp)\b", re.IGNORECASE)
_COMPOUND_TOKEN_RE = re.compile(r"has\s+['\"]([A-Za-z][a-z]+[A-Z][A-Za-z]+|[A-Za-z]+[._-][A-Za-z]+)['\"]")
# Known product/technology names that are valid standalone index terms and should not be flagged
_KNOWN_TOKENS = {
    "PowerShell", "Windows", "Linux", "Azure", "Microsoft", "Office",
    "Teams", "OneDrive", "SharePoint", "GitHub", "Active", "Directory",
}
_DEPRECATED_TI_RE = re.compile(r"\bThreatIntelligenceIndicator\b")
_UNION_STAR_RE = re.compile(r"\bunion\b[^|]*\*", re.IGNORECASE)
_JOIN_SUBQUERY_RE = re.compile(r"\b(join|union|lookup)\b[^(]*\(", re.IGNORECASE)


def _extract_join_subqueries(raw: str) -> list[tuple[int, str]]:
    """Extract subquery text and start line for join/union/lookup operators.

    Returns list of (line_number, subquery_text) tuples.
    The parser splits inline pipes, so we work directly from the raw query.
    """
    results = []
    for m in _JOIN_SUBQUERY_RE.finditer(raw):
        paren_start = m.end() - 1  # position of '('
        depth = 0
        i = paren_start
        while i < len(raw):
            if raw[i] == "(":
                depth += 1
            elif raw[i] == ")":
                depth -= 1
                if depth == 0:
                    subquery = raw[paren_start + 1: i]
                    line_num = raw[: m.start()].count("\n") + 1
                    results.append((line_num, subquery))
                    break
            i += 1
    return results


class HasSemanticMismatch(Rule):
    rule_id = "CORR001"
    category = "correctness"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "where":
                m = _COMPOUND_TOKEN_RE.search(stage.args)
                if m and m.group(1) not in _KNOWN_TOKENS:
                    findings.append(self.finding(
                        "warning", stage.line,
                        f"`has '{m.group(1)}'` — the search term looks like a compound token (camelCase/dotted). "
                        f"`has` only matches whole terms; this may silently return no results.",
                        "Verify the term is a standalone token in the index. "
                        "If it's embedded in a larger string, use `contains` instead.",
                    ))
        return findings


class JoinWithoutKind(Rule):
    rule_id = "CORR002"
    category = "correctness"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "join" and not _JOIN_KIND_RE.search(stage.args):
                findings.append(self.finding(
                    "error", stage.line,
                    "`join` without explicit `kind` defaults to `innerunique`, which silently deduplicates "
                    "on the left-side key — can create detection blind spots.",
                    "Specify `kind=inner`, `kind=leftouter`, `kind=leftanti`, or `kind=leftsemi` explicitly.",
                ))
        return findings


class NondeterministicLetWithoutMaterialize(Rule):
    rule_id = "CORR003"
    category = "correctness"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for binding in parsed.lets:
            if (binding.is_tabular
                    and binding.usage_count >= 2
                    and _NONDETERMINISTIC_RE.search(binding.expression)
                    and not _MATERIALIZE_RE.search(binding.expression)):
                findings.append(self.finding(
                    "error", binding.line,
                    f"`let {binding.name}` uses a non-deterministic function and is referenced "
                    f"{binding.usage_count}x without `materialize()` — produces different values each use.",
                    f"Wrap: `let {binding.name} = materialize(<expr>);`",
                ))
        return findings


class MissingTimeFilterInSubquery(Rule):
    rule_id = "CORR004"
    category = "correctness"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for line_num, content in _extract_join_subqueries(parsed.raw):
            if not _WHERE_TIME_FILTER_RE.search(content):
                # Determine operator name from surrounding context
                op_match = re.search(r"\b(join|union|lookup)\b", parsed.raw.splitlines()[line_num - 1], re.IGNORECASE)
                op = op_match.group(1).lower() if op_match else "join"
                findings.append(self.finding(
                    "error", line_num,
                    f"`{op}` subquery has no `TimeGenerated` filter — "
                    "may scan full data retention (up to years).",
                    f"Add `| where TimeGenerated > ago(...)` inside the {op} subquery.",
                ))
        return findings


class DeprecatedThreatIntelTable(Rule):
    rule_id = "CORR005"
    category = "correctness"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        for i, line in enumerate(parsed.lines, 1):
            if _DEPRECATED_TI_RE.search(line):
                return [self.finding(
                    "error", i,
                    "`ThreatIntelligenceIndicator` table is retiring May 31 2026.",
                    "Migrate to `ThreatIntelIndicators` (STIX-based). "
                    "See: aka.ms/MicrosoftSentinelTIBlog",
                )]
        return []


def _count_top_level_args(s: str) -> int:
    """Count comma-separated top-level arguments (not inside nested parens)."""
    depth = 0
    commas = 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            commas += 1
    return commas + 1


class SeriesDecomposeDefaultThreshold(Rule):
    rule_id = "CORR006"
    category = "correctness"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        full = parsed.raw
        for m in _SERIES_DECOMPOSE_START_RE.finditer(full):
            start = m.end()
            depth = 1
            end = start
            while end < len(full) and depth > 0:
                if full[end] == "(":
                    depth += 1
                elif full[end] == ")":
                    depth -= 1
                end += 1
            args_str = full[start:end - 1]
            if _count_top_level_args(args_str) == 1:
                line = full[: m.start()].count("\n") + 1
                findings.append(self.finding(
                    "warning", line,
                    "`series_decompose_anomalies()` uses default threshold of 1.5 — "
                    "likely too sensitive, producing high false-positive rates.",
                    "Tune the threshold: `series_decompose_anomalies(series, 3.0)` for fewer false positives.",
                ))
        return findings


class StdevWithoutZeroGuard(Rule):
    rule_id = "CORR007"
    category = "correctness"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator in ("extend", "where") and _STDEV_DIV_RE.search(stage.args):
                if not _IFF_STDEV_RE.search(stage.args):
                    findings.append(self.finding(
                        "warning", stage.line,
                        "Division by `stdev` without zero guard — causes division-by-zero when all values are identical.",
                        "Wrap: `iff(stdev_val == 0, 0.0, (val - avg_val) / stdev_val)`",
                    ))
        return findings


class ArgMaxWithoutTimeFilter(Rule):
    rule_id = "CORR008"
    category = "correctness"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for line_num, content in _extract_join_subqueries(parsed.raw):
            if _ARG_MAX_RE.search(content) and not _WHERE_TIME_FILTER_RE.search(content):
                findings.append(self.finding(
                    "warning", line_num,
                    "`arg_max(TimeGenerated, *)` in subquery without a time range filter — "
                    "scans full retention to find the latest record.",
                    "Add `| where TimeGenerated > ago(...)` before the `summarize arg_max(...)` call.",
                ))
        return findings
