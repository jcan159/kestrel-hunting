from __future__ import annotations
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.core.rules import Rule
from kestrel.environments.registry import Environment


class Engine:
    def __init__(
        self,
        rules: list[Rule],
        severity_overrides: dict[str, str] | None = None,
        disabled_rule_ids: set[str] | None = None,
    ) -> None:
        self.rules = rules
        self.severity_overrides = severity_overrides or {}
        self.disabled_rule_ids = disabled_rule_ids or set()

    def analyze(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if env.is_rule_disabled(rule.rule_id):
                continue
            if rule.rule_id in self.disabled_rule_ids:
                continue
            for finding in rule.check(parsed, env):
                if finding.rule_id in self.severity_overrides:
                    finding.severity = self.severity_overrides[finding.rule_id]
                findings.append(finding)
        return findings
