from __future__ import annotations
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class KestrelConfig:
    environment: str = "sentinel-scheduled"
    min_score: int = 70
    llm_enabled: bool = True
    llm_model: str = "claude-opus-4-6"
    default_format: str = "text"
    disabled_rule_ids: set[str] = field(default_factory=set)
    severity_overrides: dict[str, str] = field(default_factory=dict)


def load_config(path: Path | str | None) -> KestrelConfig:
    """Load config from a TOML file, filling in defaults for missing keys.

    Raises FileNotFoundError if path is not None but the file does not exist.
    """
    if path is None:
        return KestrelConfig()
    with open(Path(path), "rb") as f:
        raw = tomllib.load(f)
    kestrel = raw.get("kestrel", {})
    llm = raw.get("llm", {})
    rules = raw.get("rules", {})
    output = raw.get("output", {})
    return KestrelConfig(
        environment=kestrel.get("environment", "sentinel-scheduled"),
        min_score=kestrel.get("min_score", 70),
        llm_enabled=llm.get("enabled", True),
        llm_model=llm.get("model", "claude-opus-4-6"),
        default_format=output.get("default_format", "text"),
        disabled_rule_ids=set(rules.get("disable", [])),
        severity_overrides=dict(rules.get("overrides", {})),
    )
