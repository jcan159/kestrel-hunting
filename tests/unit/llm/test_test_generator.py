from unittest.mock import patch
from kestrel.config import KestrelConfig
from kestrel.llm.test_generator import generate_kql_tests


def test_kql_tests_calls_claude():
    cfg = KestrelConfig()
    with patch("kestrel.llm.test_generator.call_claude", return_value="datatable tests") as mock_call:
        result = generate_kql_tests("T | where x==1", "sentinel-scheduled", cfg)
    assert result == "datatable tests"
    assert mock_call.called


def test_kql_tests_user_prompt_contains_datatable_instruction():
    cfg = KestrelConfig()
    with patch("kestrel.llm.test_generator.call_claude", return_value="ok") as mock_call:
        generate_kql_tests("T | where x==1", "sentinel-nrt", cfg)
    user_prompt = mock_call.call_args[1]["user"]
    assert "datatable" in user_prompt.lower()
    assert "positive" in user_prompt.lower()
    assert "negative" in user_prompt.lower()
