from unittest.mock import patch
from kestrel.config import KestrelConfig
from kestrel.core.models import Finding
from kestrel.llm.rewriter import generate_rewrite


def test_rewrite_calls_claude():
    cfg = KestrelConfig()
    with patch("kestrel.llm.rewriter.call_claude", return_value="rewritten query") as mock_call:
        result = generate_rewrite("T | where x==1", "sentinel-scheduled", [], cfg)
    assert result == "rewritten query"
    assert mock_call.called


def test_rewrite_user_prompt_mentions_canonical_order():
    cfg = KestrelConfig()
    with patch("kestrel.llm.rewriter.call_claude", return_value="ok") as mock_call:
        generate_rewrite("T | where x==1", "sentinel-scheduled", [], cfg)
    user_prompt = mock_call.call_args[1]["user"]
    assert "canonical" in user_prompt.lower() or "let" in user_prompt.lower()


def test_rewrite_includes_findings_in_prompt():
    findings = [Finding("STR004", "structure", "warning", 2, "hardcoded threshold", "extract to let")]
    cfg = KestrelConfig()
    with patch("kestrel.llm.rewriter.call_claude", return_value="ok") as mock_call:
        generate_rewrite("T | where count > 10", "sentinel-scheduled", findings, cfg)
    user_prompt = mock_call.call_args[1]["user"]
    assert "STR004" in user_prompt
