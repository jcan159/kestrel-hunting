import pytest
from unittest.mock import patch, MagicMock
from kestrel.config import KestrelConfig
from kestrel.llm.client import build_system_prompt, call_claude


def test_build_system_prompt_contains_environment():
    prompt = build_system_prompt("sentinel-scheduled")
    assert "sentinel-scheduled" in prompt


def test_build_system_prompt_instructs_no_timegenerated_flag():
    prompt = build_system_prompt("sentinel-scheduled")
    assert "TimeGenerated" in prompt
    # Must explicitly tell Claude not to flag absent top-level TimeGenerated
    assert "do not" in prompt.lower() or "don't" in prompt.lower()


def test_build_system_prompt_instructs_no_generic_perf():
    prompt = build_system_prompt("defender-xdr")
    assert "rule engine" in prompt.lower() or "deterministic" in prompt.lower()


def test_build_system_prompt_nrt_environment():
    prompt = build_system_prompt("sentinel-nrt")
    assert "sentinel-nrt" in prompt
    assert "ingestion" in prompt.lower() or "NRT" in prompt


def test_call_claude_returns_content():
    cfg = KestrelConfig(llm_model="claude-opus-4-6")
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="test response")]
    mock_client.messages.create.return_value = mock_message

    with patch("kestrel.llm.client.anthropic.Anthropic", return_value=mock_client):
        result = call_claude(system="system prompt", user="user prompt", config=cfg)

    assert result == "test response"
    mock_client.messages.create.assert_called_once()
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-opus-4-6"
    assert call_kwargs["system"] == "system prompt"


def test_call_claude_passes_model_from_config():
    cfg = KestrelConfig(llm_model="claude-sonnet-4-6")
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="response")]
    mock_client.messages.create.return_value = mock_message

    with patch("kestrel.llm.client.anthropic.Anthropic", return_value=mock_client):
        call_claude(system="s", user="u", config=cfg)

    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-sonnet-4-6"
