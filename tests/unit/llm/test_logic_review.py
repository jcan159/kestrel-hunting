from unittest.mock import patch
from kestrel.config import KestrelConfig
from kestrel.core.models import Finding
from kestrel.llm.logic_review import generate_logic_review


def test_logic_review_calls_claude_with_query_and_findings():
    findings = [Finding("CORR002", "correctness", "error", 3, "join without kind", "fix")]
    cfg = KestrelConfig()
    with patch("kestrel.llm.logic_review.call_claude", return_value="logic review text") as mock_call:
        result = generate_logic_review(
            query="SecurityEvent | join T on Account",
            environment="sentinel-scheduled",
            findings=findings,
            config=cfg,
        )
    assert result == "logic review text"
    user_prompt = mock_call.call_args[1]["user"]
    assert "CORR002" in user_prompt
    assert "SecurityEvent" in user_prompt


def test_logic_review_includes_environment_in_system():
    cfg = KestrelConfig()
    with patch("kestrel.llm.logic_review.call_claude", return_value="ok") as mock_call:
        generate_logic_review("T | where x==1", "defender-xdr", [], cfg)
    system_prompt = mock_call.call_args[1]["system"]
    assert "defender-xdr" in system_prompt or "Defender XDR" in system_prompt


def test_logic_review_empty_findings_still_calls():
    cfg = KestrelConfig()
    with patch("kestrel.llm.logic_review.call_claude", return_value="ok") as mock_call:
        result = generate_logic_review("T | where x==1", "sentinel-scheduled", [], cfg)
    assert result == "ok"
    assert mock_call.called
