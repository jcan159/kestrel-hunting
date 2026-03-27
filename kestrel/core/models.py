from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Finding:
    rule_id: str
    category: str   # performance | correctness | sentinel | structure | documentation
    severity: str   # error | warning | info
    line: int | None
    message: str
    suggestion: str


@dataclass
class CategoryScore:
    correctness: int = 100
    performance: int = 100
    sentinel: int = 100
    structure: int = 100
    documentation: int = 100
    _overall: int | None = field(default=None, repr=False, compare=False)

    @property
    def overall(self) -> int:
        if self._overall is not None:
            return self._overall
        return int(
            self.correctness * 0.40
            + self.performance * 0.25
            + self.sentinel * 0.20
            + self.structure * 0.10
            + self.documentation * 0.05
        )


@dataclass
class AnalysisResult:
    query: str
    environment: str
    findings: list[Finding] = field(default_factory=list)
    score: CategoryScore = field(default_factory=CategoryScore)
    rewritten_query: str | None = None
    kql_tests: str | None = None
    logic_review: str | None = None
