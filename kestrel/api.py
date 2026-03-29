from __future__ import annotations
from dataclasses import dataclass, field
from kestrel.core.models import AnalysisResult, CategoryScore
from kestrel.core.parser import parse
from kestrel.core.engine import default_engine
from kestrel.core.scorer import score
from kestrel.environments.registry import get_environment

# These are populated lazily on first LLM-enabled call; declared here so
# unittest.mock.patch("kestrel.api.generate_*") can find them in the module dict.
generate_logic_review = None
generate_kql_tests = None
generate_rewrite = None


@dataclass
class AnalysisConfig:
    environment: str = "sentinel-scheduled"
    llm_enabled: bool = True
    outputs: list[str] = field(default_factory=lambda: ["report"])
    disabled_rule_ids: set[str] = field(default_factory=set)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    llm_model: str = "claude-opus-4-6"


def analyze(query: str, config: AnalysisConfig) -> AnalysisResult:
    parsed = parse(query)
    env = get_environment(config.environment)
    engine = default_engine(
        severity_overrides=config.severity_overrides,
        disabled_rule_ids=config.disabled_rule_ids,
    )
    findings = engine.analyze(parsed, env)
    category_score = score(findings)

    result = AnalysisResult(
        query=query,
        environment=config.environment,
        findings=findings,
        score=category_score,
    )

    if config.llm_enabled:
        import kestrel.api as _self
        from kestrel.llm.logic_review import generate_logic_review as _glr
        from kestrel.llm.test_generator import generate_kql_tests as _gkt
        from kestrel.llm.rewriter import generate_rewrite as _gr
        from kestrel.config import KestrelConfig

        # Populate module-level names so they remain patchable after first import
        if _self.generate_logic_review is None:
            _self.generate_logic_review = _glr
        if _self.generate_kql_tests is None:
            _self.generate_kql_tests = _gkt
        if _self.generate_rewrite is None:
            _self.generate_rewrite = _gr

        llm_cfg = KestrelConfig(llm_model=config.llm_model)

        if "logic_review" in config.outputs:
            result.logic_review = _self.generate_logic_review(query, config.environment, findings, llm_cfg)
        if "tests" in config.outputs:
            result.kql_tests = _self.generate_kql_tests(query, config.environment, llm_cfg)
        if "rewrite" in config.outputs:
            result.rewritten_query = _self.generate_rewrite(query, config.environment, findings, llm_cfg)

    return result
