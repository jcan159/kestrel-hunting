from __future__ import annotations
import re
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.core.rules import Rule
from kestrel.environments.registry import Environment

_TIME_COL_RE = re.compile(r"\b(TimeGenerated|Timestamp)\b", re.IGNORECASE)
_EXPENSIVE_OPS = re.compile(r"\b(matches\s+regex|contains|!contains)\b", re.IGNORECASE)
_AGO_RE = re.compile(r"\bago\s*\(", re.IGNORECASE)
_AGO_LITERAL_RE = re.compile(r"\bago\s*\(\s*(\d+[smhdw])\s*\)", re.IGNORECASE)
_HARDCODED_NUM_RE = re.compile(r"(?:>|<|==|!=)\s*\d+")


class TimeFilterNotFirst(Rule):
    rule_id = "STR001"
    category = "structure"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        where_stages = [s for s in parsed.pipeline if s.operator == "where"]
        if not where_stages:
            return []
        first = where_stages[0]
        if not _TIME_COL_RE.search(first.args):
            return [self.finding(
                "info", first.line,
                "Time filter is not the first `where` predicate — reduces shard elimination efficiency.",
                "Move `| where TimeGenerated > ago(...)` to be the first operator after the table reference.",
            )]
        return []


class WhereNotOrderedBySelectivity(Rule):
    rule_id = "STR002"
    category = "structure"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for i, stage in enumerate(parsed.pipeline):
            if stage.operator == "where" and _EXPENSIVE_OPS.search(stage.args):
                following_time = [
                    s for s in parsed.pipeline[i + 1:]
                    if s.operator == "where" and _TIME_COL_RE.search(s.args)
                ]
                if following_time:
                    findings.append(self.finding(
                        "info", stage.line,
                        "Expensive `where` predicate appears before a time filter — processes more data than needed.",
                        "Reorder: time filter first, then selective predicates, then regex/contains last.",
                    ))
        return findings


class NoProjectBeforeJoin(Rule):
    rule_id = "STR003"
    category = "structure"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        for i, stage in enumerate(parsed.pipeline):
            if stage.operator in ("join", "lookup"):
                before = [s.operator for s in parsed.pipeline[:i]]
                if "project" not in before and "project-away" not in before:
                    return [self.finding(
                        "info", stage.line,
                        f"No `project` before `{stage.operator}` — all source columns carried through.",
                        f"Add `| project <needed columns>` before the `{stage.operator}` to reduce row width.",
                    )]
        return []


class HardcodedLiterals(Rule):
    rule_id = "STR004"
    category = "structure"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        let_names = {b.name for b in parsed.lets}
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "where":
                # Flag hardcoded ago() calls using a duration literal (e.g. ago(1d), ago(7h))
                # Only flag when there are no let bindings (i.e., the query is entirely unparameterized)
                if _AGO_LITERAL_RE.search(stage.args) and not let_names:
                    findings.append(self.finding(
                        "info", stage.line,
                        "Hardcoded time window in `ago(...)` — extract to a `let` variable for tunability.",
                        "Add `let lookback = 1d;` at the top and use `ago(lookback)`.",
                    ))
                # Flag hardcoded numeric thresholds not involving TimeGenerated/Timestamp
                if _HARDCODED_NUM_RE.search(stage.args) and not _TIME_COL_RE.search(stage.args):
                    findings.append(self.finding(
                        "info", stage.line,
                        "Hardcoded numeric threshold — extract to a `let` variable for easier tuning.",
                        "Add `let threshold = <value>;` at the top and reference it by name.",
                    ))
        return findings


class PipelineOrderDeviation(Rule):
    rule_id = "STR005"
    category = "structure"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        operators = [s.operator for s in parsed.pipeline]
        for i, op in enumerate(operators):
            if op == "summarize":
                remaining = operators[i + 1:]
                if "join" in remaining or "lookup" in remaining:
                    return [self.finding(
                        "info", parsed.pipeline[i].line,
                        "`summarize` appears before `join`/`lookup` — deviates from canonical pipeline order.",
                        "Canonical order: filter → project → join/lookup → summarize → final shaping.",
                    )]
        return []
