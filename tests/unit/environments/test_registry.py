import pytest
from kestrel.environments.registry import get_environment, Environment, ENVIRONMENTS


def test_get_sentinel_scheduled():
    env = get_environment("sentinel-scheduled")
    assert env.name == "sentinel-scheduled"


def test_get_sentinel_nrt():
    env = get_environment("sentinel-nrt")
    assert env.name == "sentinel-nrt"


def test_get_defender_xdr():
    env = get_environment("defender-xdr")
    assert env.name == "defender-xdr"


def test_get_defender_xdr_continuous():
    env = get_environment("defender-xdr-continuous")
    assert env.name == "defender-xdr-continuous"


def test_unknown_environment_raises():
    with pytest.raises(ValueError, match="Unknown environment"):
        get_environment("invalid-env")


def test_sentinel_scheduled_sent001_active():
    env = get_environment("sentinel-scheduled")
    assert not env.is_rule_disabled("SENT001")


def test_sentinel_nrt_sent001_disabled():
    # SENT001 (search */union * ban) is Scheduled-only
    env = get_environment("sentinel-nrt")
    assert env.is_rule_disabled("SENT001")


def test_sentinel_nrt_sent007_active():
    # SENT007 (top-level TimeGenerated misleading for NRT) only fires for NRT
    env = get_environment("sentinel-nrt")
    assert not env.is_rule_disabled("SENT007")


def test_sentinel_scheduled_sent007_disabled():
    env = get_environment("sentinel-scheduled")
    assert env.is_rule_disabled("SENT007")


def test_defender_xdr_continuous_sent008_active():
    env = get_environment("defender-xdr-continuous")
    assert not env.is_rule_disabled("SENT008")


def test_defender_xdr_standard_sent008_disabled():
    env = get_environment("defender-xdr")
    assert env.is_rule_disabled("SENT008")


def test_all_environments_present():
    assert set(ENVIRONMENTS.keys()) == {
        "sentinel-scheduled",
        "sentinel-nrt",
        "defender-xdr",
        "defender-xdr-continuous",
    }
