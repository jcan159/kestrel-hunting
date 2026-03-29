from __future__ import annotations
from kestrel.config import KestrelConfig
from kestrel.core.models import Finding
from kestrel.llm.client import build_system_prompt, call_claude


def generate_logic_review(
    query: str,
    environment: str,
    findings: list[Finding],
    config: KestrelConfig,
) -> str:
    system = build_system_prompt(environment)
    findings_block = "\n".join(
        f"  [{f.severity.upper()}] {f.rule_id}: {f.message}" for f in findings
    ) or "  (none)"
    user = (
        f"Review the detection logic of this KQL query for the {environment} environment.\n\n"
        f"Query:\n```kql\n{query}\n```\n\n"
        f"Rule engine findings (already reported — do not repeat these):\n{findings_block}\n\n"
        "Provide:\n"
        "1. What this query is trying to detect (inferred intent)\n"
        "2. Whether the logic achieves that intent\n"
        "3. Detection gaps or bypass conditions an attacker could exploit\n"
        "4. Where on the precision/recall spectrum this sits (precise/brittle vs broad/resilient)\n"
        "5. Whether a statistical enhancement (z-score, series_decompose_anomalies, entropy) would improve it\n"
        "6. Whether an ASIM parser would broaden coverage\n"
    )
    return call_claude(system=system, user=user, config=config)
