import pytest
from pathlib import Path
from kestrel.config import KestrelConfig, load_config


def test_load_config_defaults_when_no_file():
    cfg = load_config(None)
    assert cfg.environment == "sentinel-scheduled"
    assert cfg.min_score == 70
    assert cfg.llm_enabled is True
    assert cfg.llm_model == "claude-opus-4-6"
    assert cfg.default_format == "text"
    assert cfg.disabled_rule_ids == set()
    assert cfg.severity_overrides == {}


def test_load_config_from_toml(tmp_path):
    toml_file = tmp_path / "kestrel.toml"
    toml_file.write_text(
        "[kestrel]\n"
        "environment = \"sentinel-nrt\"\n"
        "min_score = 80\n"
        "\n"
        "[llm]\n"
        "enabled = false\n"
        "model = \"claude-sonnet-4-6\"\n"
        "\n"
        "[rules]\n"
        "disable = [\"DOC001\", \"DOC002\"]\n"
        "\n"
        "[rules.overrides]\n"
        "PERF001 = \"info\"\n"
        "\n"
        "[output]\n"
        "default_format = \"json\"\n"
    )
    cfg = load_config(toml_file)
    assert cfg.environment == "sentinel-nrt"
    assert cfg.min_score == 80
    assert cfg.llm_enabled is False
    assert cfg.llm_model == "claude-sonnet-4-6"
    assert cfg.default_format == "json"
    assert cfg.disabled_rule_ids == {"DOC001", "DOC002"}
    assert cfg.severity_overrides == {"PERF001": "info"}


def test_load_config_partial_toml(tmp_path):
    toml_file = tmp_path / "kestrel.toml"
    toml_file.write_text("[kestrel]\nmin_score = 90\n")
    cfg = load_config(toml_file)
    assert cfg.min_score == 90
    assert cfg.environment == "sentinel-scheduled"   # default preserved
    assert cfg.llm_enabled is True                   # default preserved
