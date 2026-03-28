from __future__ import annotations
import re
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.core.rules import Rule
from kestrel.environments.registry import Environment

_ADX_CLUSTER_RE = re.compile(r"\bcluster\s*\(", re.IGNORECASE)
_BAG_UNPACK_RE = re.compile(r"\bbag_unpack\b", re.IGNORECASE)
_COLUMN_IF_EXISTS_RE = re.compile(r"\bcolumn_ifexists\b", re.IGNORECASE)
_TIME_FILTER_RE = re.compile(r"\b(TimeGenerated|Timestamp)\s*(>|<|between|==)", re.IGNORECASE)
_TIMESTAMP_FILTER_RE = re.compile(r"\bTimestamp\s*(>|<|between|==)", re.IGNORECASE)
_UNION_STAR_RE = re.compile(r"\bunion\b[^|]*\*", re.IGNORECASE)
_INLINE_COMMENT_RE = re.compile(r"//.*$")

# Tables with ASIM equivalents
_ASIM_MAP = {
    "DnsEvents": "_Im_Dns",
    "W3CIISLog": "_Im_WebSession",
    "SigninLogs": "_Im_Authentication",
    "AADNonInteractiveUserSignInLogs": "_Im_Authentication",
    "Syslog": "_Im_Syslog",
    "CommonSecurityLog": "_Im_NetworkSession",
    "SecurityEvent": "_Im_Authentication",
}

# Operators allowed in Defender XDR Continuous (NRT) mode
_CONTINUOUS_ALLOWED_OPS = {
    "extend", "project", "print", "where", "parse",
    "project-away", "project-rename", "datatable",
}

# Entity identifier columns required in Defender XDR output
_ENTITY_IDENTIFIERS = {
    "DeviceId", "DeviceName", "RemoteDeviceName", "RecipientEmailAddress",
    "SenderFromAddress", "SenderMailFromAddress", "SenderObjectId",
    "RecipientObjectId", "AccountObjectId", "AccountSid", "AccountUpn",
    "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn",
    "InitiatingProcessAccountObjectId",
}


class SearchOrUnionStar(Rule):
    rule_id = "SENT001"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        # Check pipeline stages (comment-stripped) for union *
        for stage in parsed.pipeline:
            if stage.operator == "union" and (
                stage.args.strip() == "*" or _UNION_STAR_RE.search(stage.args)
            ):
                findings.append(self.finding(
                    "error", stage.line,
                    "`union *` is explicitly prohibited in Sentinel Scheduled Analytics Rules.",
                    "Scope to a specific table: `SecurityEvent | where ...`",
                ))
            if stage.operator == "search" and stage.args.strip().startswith("*"):
                findings.append(self.finding(
                    "error", stage.line,
                    "`search *` is explicitly prohibited in Sentinel Scheduled Analytics Rules.",
                    "Scope to a specific table: `SecurityEvent | where ...`",
                ))
        # Also check table reference for bare `search *`
        if re.match(r"search\s+\*", parsed.table, re.IGNORECASE):
            findings.append(self.finding(
                "error", 1,
                "`search *` is explicitly prohibited in Sentinel Scheduled Analytics Rules.",
                "Scope to a specific table: `SecurityEvent | where ...`",
            ))
        return findings


class QueryTooLong(Rule):
    rule_id = "SENT002"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        if parsed.char_count > 10_000:
            return [self.finding(
                "error", None,
                f"Query is {parsed.char_count:,} characters — exceeds Sentinel's 10,000 character limit.",
                "Extract reusable logic into saved workspace functions to reduce query length.",
            )]
        return []


class AdxCrossClusterFunction(Rule):
    rule_id = "SENT003"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        for i, line in enumerate(parsed.lines, 1):
            clean = _INLINE_COMMENT_RE.sub("", line)
            if _ADX_CLUSTER_RE.search(clean):
                return [self.finding(
                    "error", i,
                    "ADX cross-cluster reference (`cluster(...)`) is not supported in Log Analytics.",
                    "Remove the cluster/database qualifier and reference the table directly.",
                )]
        return []


class BagUnpackWithoutColumnIfExists(Rule):
    rule_id = "SENT004"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        has_bag_unpack = any(_BAG_UNPACK_RE.search(line) for line in parsed.lines)
        if not has_bag_unpack:
            return []
        has_guard = any(_COLUMN_IF_EXISTS_RE.search(line) for line in parsed.lines)
        if not has_guard:
            return [self.finding(
                "error", None,
                "`bag_unpack` used without `column_ifexists()` guard — query will fail if a projected column is absent.",
                "Replace `project field1` with `project field1 = column_ifexists('field1', '')`",
            )]
        return []


class TimeGeneratedNotInOutput(Rule):
    rule_id = "SENT005"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        project_stages = [s for s in parsed.pipeline if s.operator == "project"]
        if not project_stages:
            return []  # No project = all columns returned, including TimeGenerated
        last_project = project_stages[-1]
        if "TimeGenerated" not in last_project.args and "Timestamp" not in last_project.args:
            return [self.finding(
                "error", last_project.line,
                "`TimeGenerated` not returned in query output — required for Scheduled rule lookback to work correctly.",
                "Add `TimeGenerated` to the final `project` statement.",
            )]
        return []


class RawTableInsteadOfAsim(Rule):
    rule_id = "SENT006"
    category = "sentinel"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        if parsed.table in _ASIM_MAP:
            asim = _ASIM_MAP[parsed.table]
            return [self.finding(
                "info", 1,
                f"Raw table `{parsed.table}` used — an ASIM parser exists that covers multiple data sources.",
                f"Consider using `{asim}(...)` to detect across all sources that map to this schema.",
            )]
        return []


class NrtTopLevelTimeFilter(Rule):
    rule_id = "SENT007"
    category = "sentinel"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        for stage in parsed.pipeline:
            if stage.operator == "where" and _TIME_FILTER_RE.search(stage.args):
                return [self.finding(
                    "warning", stage.line,
                    "NRT rules use ingestion time, not `TimeGenerated`. "
                    "A top-level `TimeGenerated` filter may exclude recently ingested events.",
                    "Remove the top-level `TimeGenerated` filter — the NRT engine handles the 1-minute lookback automatically.",
                )]
        return []


class ContinuousJoinOrUnion(Rule):
    rule_id = "SENT008"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator in ("join", "union", "externaldata"):
                findings.append(self.finding(
                    "error", stage.line,
                    f"`{stage.operator}` is not supported in Defender XDR Continuous (NRT) detections.",
                    "Use standard frequency (hourly/daily) for queries requiring joins or unions.",
                ))
        return findings


class ContinuousUnsupportedOperator(Rule):
    rule_id = "SENT009"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings = []
        for stage in parsed.pipeline:
            if stage.operator not in _CONTINUOUS_ALLOWED_OPS:
                findings.append(self.finding(
                    "error", stage.line,
                    f"`{stage.operator}` is not in the Continuous (NRT) supported operator allowlist.",
                    f"Supported operators: {', '.join(sorted(_CONTINUOUS_ALLOWED_OPS))}. "
                    "Use standard frequency for queries requiring this operator.",
                ))
        return findings


class MissingEntityIdentifier(Rule):
    rule_id = "SENT010"
    category = "sentinel"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        project_stages = [s for s in parsed.pipeline if s.operator == "project"]
        if not project_stages:
            return []  # All columns returned — entity identifiers present
        last_project = project_stages[-1]
        projected_cols = {c.strip() for c in last_project.args.split(",")}
        if not projected_cols.intersection(_ENTITY_IDENTIFIERS):
            return [self.finding(
                "error", last_project.line,
                "No entity identifier column in output — Defender XDR requires at least one of: "
                f"{', '.join(sorted(_ENTITY_IDENTIFIERS)[:5])}... (and others).",
                "Add the relevant entity identifier (e.g., `DeviceId`, `AccountObjectId`) to the `project` statement.",
            )]
        return []


class TimestampFilteredInXdr(Rule):
    rule_id = "SENT011"
    category = "sentinel"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        for stage in parsed.pipeline:
            if stage.operator == "where" and _TIMESTAMP_FILTER_RE.search(stage.args):
                return [self.finding(
                    "warning", stage.line,
                    "Filtering on `Timestamp` in a Defender XDR Custom Detection — the service pre-filters by detection frequency.",
                    "Remove the `Timestamp` filter; let the detection frequency (hourly/daily) control the lookback.",
                )]
        return []
