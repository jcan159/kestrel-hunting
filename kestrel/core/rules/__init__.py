from __future__ import annotations
from abc import ABC, abstractmethod
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.environments.registry import Environment


class Rule(ABC):
    rule_id: str
    category: str
    default_severity: str

    def finding(self, severity: str, line: int | None, message: str, suggestion: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            category=self.category,
            severity=severity,
            line=line,
            message=message,
            suggestion=suggestion,
        )

    @property
    @abstractmethod
    def rule_id(self) -> str: ...

    @property
    @abstractmethod
    def category(self) -> str: ...

    @property
    @abstractmethod
    def default_severity(self) -> str: ...

    @abstractmethod
    def check(self, parsed: ParsedQuery, env: Environment) -> list[Finding]: ...
