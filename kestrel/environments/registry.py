from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Environment:
    name: str
    display_name: str
    disabled_rules: set[str] = field(default_factory=set)

    def is_rule_disabled(self, rule_id: str) -> bool:
        return rule_id in self.disabled_rules


# Rules that only apply to specific environments are disabled in others.
# Rules not listed in any disabled_rules set are active everywhere.
_SENT_NRT_ONLY = {"SENT007"}
_SENT_SCHEDULED_ONLY = {"SENT001", "SENT002", "SENT003", "SENT004", "SENT005"}
_DEFENDER_XDR_ONLY = {"SENT010", "SENT011"}
_DEFENDER_CONTINUOUS_ONLY = {"SENT008", "SENT009"}

ENVIRONMENTS: dict[str, Environment] = {
    "sentinel-scheduled": Environment(
        name="sentinel-scheduled",
        display_name="Microsoft Sentinel — Scheduled Analytics Rule",
        disabled_rules=_SENT_NRT_ONLY | _DEFENDER_XDR_ONLY | _DEFENDER_CONTINUOUS_ONLY,
    ),
    "sentinel-nrt": Environment(
        name="sentinel-nrt",
        display_name="Microsoft Sentinel — NRT Analytics Rule",
        disabled_rules=_SENT_SCHEDULED_ONLY | _DEFENDER_XDR_ONLY | _DEFENDER_CONTINUOUS_ONLY,
    ),
    "defender-xdr": Environment(
        name="defender-xdr",
        display_name="Microsoft Defender XDR — Custom Detection",
        disabled_rules=_SENT_NRT_ONLY | _SENT_SCHEDULED_ONLY | _DEFENDER_CONTINUOUS_ONLY,
    ),
    "defender-xdr-continuous": Environment(
        name="defender-xdr-continuous",
        display_name="Microsoft Defender XDR — Continuous (NRT) Detection",
        disabled_rules=_SENT_NRT_ONLY | _SENT_SCHEDULED_ONLY,
    ),
}


def get_environment(name: str) -> Environment:
    if name not in ENVIRONMENTS:
        raise ValueError(f"Unknown environment: '{name}'. Valid: {sorted(ENVIRONMENTS)}")
    return ENVIRONMENTS[name]
