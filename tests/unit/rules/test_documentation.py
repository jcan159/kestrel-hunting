# tests/unit/rules/test_documentation.py
from kestrel.core.parser import parse
from kestrel.core.rules.documentation import MissingMitreTag, MissingAuthorHeader, MissingDescription
from kestrel.environments.registry import get_environment

ENV = get_environment("sentinel-scheduled")


def fires(rule, query):
    return rule.check(parse(query), ENV)


DOCUMENTED_QUERY = """\
// Description: Detects brute force sign-in attempts
// MITRE ATT&CK: T1110 - Brute Force
// Author: SOC Team | Last Updated: 2026-03-01
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
"""


def test_doc001_missing_mitre_fires():
    q = "// Author: SOC\nSecurityEvent | where EventID == 1"
    assert any(f.rule_id == "DOC001" for f in fires(MissingMitreTag(), q))


def test_doc001_with_mitre_no_fire():
    assert fires(MissingMitreTag(), DOCUMENTED_QUERY) == []


def test_doc001_technique_id_no_fire():
    q = "// T1110.001\nSecurityEvent | where EventID == 4625"
    assert fires(MissingMitreTag(), q) == []


def test_doc002_missing_author_fires():
    q = "// Description: detects things\n// MITRE: T1110\nSecurityEvent | where EventID == 1"
    assert any(f.rule_id == "DOC002" for f in fires(MissingAuthorHeader(), q))


def test_doc002_with_author_no_fire():
    assert fires(MissingAuthorHeader(), DOCUMENTED_QUERY) == []


def test_doc003_missing_description_fires():
    q = "// Author: SOC\n// MITRE: T1110\nSecurityEvent | where EventID == 1"
    assert any(f.rule_id == "DOC003" for f in fires(MissingDescription(), q))


def test_doc003_with_description_no_fire():
    assert fires(MissingDescription(), DOCUMENTED_QUERY) == []
