from __future__ import annotations
import re
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.core.rules import Rule
from kestrel.environments.registry import Environment

_CONTAINS_RE = re.compile(r"\bcontains\b", re.IGNORECASE)
_HAS_RE = re.compile(r"\bhas\b", re.IGNORECASE)
_REGEX_OP_RE = re.compile(r"\bmatches\s+regex\b", re.IGNORECASE)
_SEARCH_STAR_RE = re.compile(r"\bsearch\s+\*", re.IGNORECASE)
_UNION_STAR_RE = re.compile(r"\bunion\b[^|]*\*", re.IGNORECASE)
_CASE_INSENSITIVE_RE = re.compile(r"\s(=~|!~|in~|!in~|has_any~)\s", re.IGNORECASE)
_GRAPH_PATH_RE = re.compile(r"\[(\w+)\*(\d+)\.\.(\d+)\]")
_SERIALIZE_OPS = {"serialize", "sort", "order"}
_HINT_RE = re.compile(r"\bhint\.", re.IGNORECASE)
_MATERIALIZE_RE = re.compile(r"\bmaterialize\s*\(", re.IGNORECASE)
_DCOUNT_RE = re.compile(r"\bdcount\s*\(", re.IGNORECASE)
_TOSCALAR_RE = re.compile(r"\btoscalar\s*\(", re.IGNORECASE)


class ContainsInsteadOfHas(Rule):
    rule_id = "PERF001"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "where" and _CONTAINS_RE.search(stage.args):
                findings.append(self.finding(
                    "warning", stage.line,
                    "`contains` performs a full substring scan, bypassing the term index.",
                    "If the search string is a whole token, use `has` instead. "
                    "Note: `has` does NOT match substrings within compound tokens.",
                ))
        return findings


class RegexWithoutPrefilter(Rule):
    rule_id = "PERF002"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for i, stage in enumerate(parsed.pipeline):
            if stage.operator == "where" and _REGEX_OP_RE.search(stage.args):
                prev_has = any(
                    s.operator == "where" and (_HAS_RE.search(s.args) or _CONTAINS_RE.search(s.args))
                    for s in parsed.pipeline[:i]
                )
                same_stage_has = _HAS_RE.search(stage.args) or _CONTAINS_RE.search(stage.args)
                if not prev_has and not same_stage_has:
                    findings.append(self.finding(
                        "warning", stage.line,
                        "`matches regex` without a preceding `has` pre-filter — evaluates regex on every row.",
                        "Add `| where Column has 'literal'` before the regex step to reduce the row count first.",
                    ))
        return findings


class SearchOrUnionStarPerf(Rule):
    rule_id = "PERF003"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        # Check pipeline stages (already comment-stripped)
        for stage in parsed.pipeline:
            if stage.operator == "union" and re.search(r"\*", stage.args):
                findings.append(self.finding(
                    "warning", stage.line,
                    "`union *` scans all tables in the workspace.",
                    "Scope to specific tables: `union Table1, Table2` or use specific table queries.",
                ))
            if stage.operator == "search" and stage.args.strip().startswith("*"):
                findings.append(self.finding(
                    "warning", stage.line,
                    "`search *` scans all tables in the workspace.",
                    "Scope to a specific table: replace `search *` with `TableName | where ...`.",
                ))
        # Also check the table reference itself for bare `search *`
        if re.match(r"search\s+\*", parsed.table, re.IGNORECASE):
            findings.append(self.finding(
                "warning", 1,
                "`search *` scans all tables in the workspace.",
                "Scope to a specific table: replace `search *` with `TableName | where ...`.",
            ))
        return findings


class FilterOnComputedColumn(Rule):
    rule_id = "PERF004"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        computed: set[str] = set()
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "extend":
                # Only match assignment targets: word= at start of each comma-delimited segment
                # Reject segments where = is immediately followed by = (comparison operator)
                for segment in stage.args.split(","):
                    m = re.match(r"\s*(\w+)\s*=[^=]", segment)
                    if m:
                        computed.add(m.group(1))
            if stage.operator == "where":
                for name in computed:
                    if re.search(r"\b" + re.escape(name) + r"\b", stage.args):
                        findings.append(self.finding(
                            "warning", stage.line,
                            f"`where` filters on computed column `{name}` — prevents index optimization.",
                            f"Apply the filter on the original column before the `extend` step.",
                        ))
        return findings


class NoEarlyProject(Rule):
    rule_id = "PERF005"
    category = "performance"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        operators = [s.operator for s in parsed.pipeline]
        has_project_before_join = False
        for op in operators:
            if op in ("project", "project-away"):
                has_project_before_join = True
                break
            if op in ("join", "summarize", "lookup"):
                break
        if not has_project_before_join and any(op in ("join", "lookup") for op in operators):
            join_stage = next(s for s in parsed.pipeline if s.operator in ("join", "lookup"))
            return [self.finding(
                "info", join_stage.line,
                "No `project` before `join`/`lookup` — all columns carried through join.",
                "Add `| project <needed columns>` before the join to reduce row width.",
            )]
        return []


class LetWithoutMaterialize(Rule):
    rule_id = "PERF006"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for binding in parsed.lets:
            if binding.is_tabular and binding.usage_count >= 2:
                if not _MATERIALIZE_RE.search(binding.expression):
                    findings.append(self.finding(
                        "warning", binding.line,
                        f"Tabular `let {binding.name}` used {binding.usage_count}× without `materialize()` — re-evaluated each time.",
                        f"Wrap the expression: `let {binding.name} = materialize(<expr>);`",
                    ))
        return findings


class DuplicateTableScan(Rule):
    rule_id = "PERF007"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        # Extract table name from subquery: take everything before the first pipe
        subquery_tables: list[str] = []
        for stage in parsed.pipeline:
            if stage.operator in ("join", "union"):
                # Table name is the first word of the subquery arg (before any |)
                subquery_text = stage.args.split("|")[0].strip()
                # Strip parentheses for subquery like (Table | ...)
                subquery_text = subquery_text.lstrip("(").strip()
                # Take the first PascalCase word
                m = re.match(r"([A-Z][A-Za-z0-9_]*)", subquery_text)
                if m:
                    subquery_tables.append(m.group(1))
        seen: set[str] = set()
        duplicates: set[str] = set()
        for t in subquery_tables:
            if t in seen:
                duplicates.add(t)
            seen.add(t)
        if parsed.table in subquery_tables:
            duplicates.add(parsed.table)
        if duplicates:
            return [self.finding(
                "warning", None,
                f"Table(s) scanned multiple times in subqueries: {', '.join(sorted(duplicates))}",
                "Use a single scan with conditional aggregation: "
                "`summarize A = countif(cond1), B = countif(cond2) by Key`",
            )]
        return []


class JoinWithoutHint(Rule):
    rule_id = "PERF008"
    category = "performance"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "join":
                if not _HINT_RE.search(stage.args):
                    findings.append(self.finding(
                        "info", stage.line,
                        "`join` without `hint.strategy` — no join distribution hint specified.",
                        "For small right side: add `hint.strategy=broadcast`. "
                        "For large keys: add `hint.shufflekey=<key>`.",
                    ))
        return findings


class GraphMatchDeepPath(Rule):
    rule_id = "PERF009"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "graph-match":
                m = _GRAPH_PATH_RE.search(stage.args)
                if m and int(m.group(3)) > 5:
                    findings.append(self.finding(
                        "warning", stage.line,
                        f"`graph-match` path depth {m.group(3)} exceeds recommended maximum of 5 hops.",
                        "Reduce max depth to ≤5 or pre-filter the graph nodes/edges before traversal.",
                    ))
        return findings


class DcountWithoutToscalar(Rule):
    rule_id = "PERF010"
    category = "performance"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        # Case 1: let binding with dcount used 2+ times without materialize/toscalar
        for binding in parsed.lets:
            if _DCOUNT_RE.search(binding.expression) and not _TOSCALAR_RE.search(binding.expression):
                if binding.usage_count >= 2:
                    findings.append(self.finding(
                        "info", binding.line,
                        f"`let {binding.name}` uses `dcount()` without `toscalar()` and is referenced {binding.usage_count}× — non-deterministic.",
                        f"Wrap with toscalar: `let {binding.name} = toscalar(<expr> | summarize dcount(...));`",
                    ))
        # Case 2: dcount appears in a join/union subquery without toscalar wrapping
        for stage in parsed.pipeline:
            if stage.operator in ("join", "union"):
                if _DCOUNT_RE.search(stage.args) and not _TOSCALAR_RE.search(stage.args):
                    # Also check if dcount appears elsewhere in the query (let or another stage)
                    other_dcount = any(
                        _DCOUNT_RE.search(b.expression) for b in parsed.lets
                    ) or any(
                        _DCOUNT_RE.search(s.args) for s in parsed.pipeline
                        if s is not stage and s.operator in ("join", "union", "summarize")
                    )
                    if other_dcount:
                        findings.append(self.finding(
                            "info", stage.line,
                            "`dcount()` computed multiple times in the query without `toscalar()` — non-deterministic results.",
                            "Extract the dcount into a `let` with `toscalar()`: `let cnt = toscalar(<expr> | summarize dcount(...));`",
                        ))
        return findings


class SerializeEarly(Rule):
    rule_id = "PERF011"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for i, stage in enumerate(parsed.pipeline):
            if stage.operator in _SERIALIZE_OPS:
                remaining = [s.operator for s in parsed.pipeline[i + 1:]]
                if any(op in ("summarize", "join", "where") for op in remaining):
                    findings.append(self.finding(
                        "warning", stage.line,
                        f"`{stage.operator}` forces sequential processing but expensive operators follow it.",
                        f"Move `{stage.operator}` as late in the pipeline as possible.",
                    ))
        return findings


class CaseInsensitiveOperator(Rule):
    rule_id = "PERF012"
    category = "performance"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator == "where" and _CASE_INSENSITIVE_RE.search(stage.args):
                findings.append(self.finding(
                    "info", stage.line,
                    "Case-insensitive operator (`=~`, `in~`, etc.) used where exact case is likely known.",
                    "Use `==`, `in`, `has_cs` for ~20% faster evaluation when case is deterministic.",
                ))
        return findings
