from kestrel.core.engine import Engine
from kestrel.core.models import Finding
from kestrel.core.parser import parse
from kestrel.core.rules import Rule
from kestrel.core.parser import ParsedQuery
from kestrel.environments.registry import get_environment


class AlwaysFires(Rule):
    rule_id = "TEST001"
    category = "performance"
    default_severity = "warning"

    def check(self, parsed: ParsedQuery, env) -> list[Finding]:
        return [Finding(rule_id="TEST001", category="performance",
                        severity="warning", line=1,
                        message="test", suggestion="test")]


class NeverFires(Rule):
    rule_id = "TEST002"
    category = "correctness"
    default_severity = "error"

    def check(self, parsed: ParsedQuery, env) -> list[Finding]:
        return []


def make_engine(*rules, severity_overrides=None):
    return Engine(list(rules), severity_overrides=severity_overrides or {})


def test_engine_returns_findings_from_rule():
    engine = make_engine(AlwaysFires())
    env = get_environment("sentinel-scheduled")
    findings = engine.analyze(parse("SecurityEvent | where EventID == 1"), env)
    assert len(findings) == 1
    assert findings[0].rule_id == "TEST001"


def test_engine_no_findings_when_rule_silent():
    engine = make_engine(NeverFires())
    env = get_environment("sentinel-scheduled")
    findings = engine.analyze(parse("SecurityEvent | where EventID == 1"), env)
    assert findings == []


# TODO: uncomment after Task 8 (kestrel/core/rules/sentinel.py does not exist yet)
# def test_engine_skips_disabled_rule():
#     # SENT001 is disabled for sentinel-nrt
#     from kestrel.core.rules.sentinel import SearchOrUnionStar
#     engine = Engine([SearchOrUnionStar()])
#     env = get_environment("sentinel-nrt")
#     findings = engine.analyze(parse("search *"), env)
#     assert findings == []


def test_engine_severity_override():
    engine = Engine([AlwaysFires()], severity_overrides={"TEST001": "info"})
    env = get_environment("sentinel-scheduled")
    findings = engine.analyze(parse("T | where x == 1"), env)
    assert findings[0].severity == "info"


def test_engine_multiple_rules():
    engine = make_engine(AlwaysFires(), NeverFires())
    env = get_environment("sentinel-scheduled")
    findings = engine.analyze(parse("T | where x == 1"), env)
    assert len(findings) == 1
