from __future__ import annotations
from kestrel.config import KestrelConfig
from kestrel.core.models import Finding
from kestrel.llm.client import build_system_prompt, call_claude


def generate_rewrite(
    query: str,
    environment: str,
    findings: list[Finding],
    config: KestrelConfig,
) -> str:
    system = build_system_prompt(environment)
    findings_block = "\n".join(
        f"  [{f.severity.upper()}] {f.rule_id}: {f.message} — {f.suggestion}"
        for f in findings
    ) or "  (none)"
    user = (
        f"Rewrite the following KQL detection rule for the {environment} environment "
        "following canonical pipeline order and best practices.\n\n"
        f"Original query:\n```kql\n{query}\n```\n\n"
        f"Rule engine findings to address:\n{findings_block}\n\n"
        "Requirements:\n"
        "1. Follow canonical pipeline order: time filter → selective where → project → join/lookup → summarize → final shaping\n"
        "2. Extract hardcoded numeric/time literals into let variables at the top\n"
        "3. Add a documentation header with MITRE tag placeholder, description, and author placeholder\n"
        "4. Respect all environment constraints — do not introduce unsupported operators\n"
        "5. Add a brief inline changelog (// Changed: ...) explaining each significant change\n"
        "Return only the rewritten query with inline comments. No prose outside of comments.\n"
    )
    return call_claude(system=system, user=user, config=config)
