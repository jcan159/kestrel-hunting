from __future__ import annotations
from kestrel.config import KestrelConfig
from kestrel.llm.client import build_system_prompt, call_claude


def generate_kql_tests(
    query: str,
    environment: str,
    config: KestrelConfig,
) -> str:
    system = build_system_prompt(environment)
    user = (
        f"Generate a runnable KQL test suite for this {environment} detection rule.\n\n"
        f"Query:\n```kql\n{query}\n```\n\n"
        "Requirements:\n"
        "- Use datatable(...)[...] syntax to construct test data\n"
        "- Provide 2-3 positive cases (rows that SHOULD trigger the detection)\n"
        "- Provide 2-3 negative cases (rows that should NOT trigger, including known bypass attempts)\n"
        "- Comment each block explaining what it validates and why\n"
        "- Return only runnable KQL, no prose explanation outside of comments\n"
    )
    return call_claude(system=system, user=user, config=config)
