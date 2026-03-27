from __future__ import annotations
from abc import ABC, abstractmethod
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.environments.registry import Environment


class Rule(ABC):
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
