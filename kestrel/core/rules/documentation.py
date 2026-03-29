from __future__ import annotations
import re
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.core.rules import Rule
from kestrel.environments.registry import Environment

_MITRE_RE = re.compile(r"T\d{4}(?:\.\d{3})?|ATT&CK|MITRE", re.IGNORECASE)
_AUTHOR_RE = re.compile(r"\bauthor\b", re.IGNORECASE)
_DESCRIPTION_RE = re.compile(r"\b(description|desc|detects|purpose)\b", re.IGNORECASE)


class MissingMitreTag(Rule):
    rule_id = "DOC001"
    category = "documentation"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        if not any(_MITRE_RE.search(c) for c in parsed.comments):
            return [self.finding(
                "info", None,
                "No MITRE ATT&CK tactic or technique reference found.",
                "Add a comment: `// MITRE ATT&CK: T1110 - Brute Force`",
            )]
        return []


class MissingAuthorHeader(Rule):
    rule_id = "DOC002"
    category = "documentation"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        if not any(_AUTHOR_RE.search(c) for c in parsed.comments):
            return [self.finding(
                "info", None,
                "No author or last-updated header found.",
                "Add a comment: `// Author: <name> | Last Updated: YYYY-MM-DD`",
            )]
        return []


class MissingDescription(Rule):
    rule_id = "DOC003"
    category = "documentation"
    default_severity = "info"

    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        if not any(_DESCRIPTION_RE.search(c) for c in parsed.comments):
            return [self.finding(
                "info", None,
                "No description comment explaining what this query detects.",
                "Add a comment: `// Description: Detects <behaviour> by monitoring <data source>`",
            )]
        return []
