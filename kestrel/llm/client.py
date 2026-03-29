from __future__ import annotations
import anthropic
from kestrel.config import KestrelConfig

_MAX_TOKENS = 4096

_ENV_CONTEXT = {
    "sentinel-scheduled": (
        "You are analyzing a Microsoft Sentinel scheduled analytics rule. "
        "The rule engine handles lookback via the configured query frequency and lookback window — "
        "do NOT flag the absence of a top-level TimeGenerated filter as an issue. "
        "TimeGenerated must appear in query output for Sentinel's entity mapping. "
        "search * and union * are explicitly disallowed in scheduled rules. "
        "ADX cross-cluster functions are not supported in Log Analytics."
    ),
    "sentinel-nrt": (
        "You are analyzing a Microsoft Sentinel Near Real-Time (NRT) analytics rule. "
        "NRT rules use ingestion time, not TimeGenerated — a top-level TimeGenerated filter "
        "would be misleading and should NOT be suggested. "
        "NRT rules have a fixed 1-minute lookback. "
        "do NOT flag the absence of a top-level TimeGenerated filter as an issue."
    ),
    "defender-xdr": (
        "You are analyzing a Microsoft Defender XDR custom detection rule. "
        "The service pre-filters on Timestamp — do NOT suggest adding a Timestamp filter. "
        "Required entity identifier columns must appear in output per source table. "
        "The rule has 10-minute / 100k row / 64 MB execution limits."
    ),
    "defender-xdr-continuous": (
        "You are analyzing a Microsoft Defender XDR continuous (NRT) custom detection rule. "
        "Only a single table is allowed — no join, union, or externaldata. "
        "Only extend, project, where, parse, project-away, project-rename are supported. "
        "The service pre-filters on Timestamp — do NOT suggest adding a Timestamp filter."
    ),
}

_SHARED_CONSTRAINTS = """
Important constraints:
- Do NOT give generic performance advice already covered by the deterministic rule engine findings provided to you. Those findings are shown in the user message. Focus on detection logic gaps, not re-stating what the engine already found.
- Do NOT suggest removing project operators that may be required for entity mapping.
- Do NOT suggest adding or removing time filters unless the logic is provably incorrect for the specific environment above.
- Treat the environment constraints listed above as fixed facts about the execution context.
- Be specific to this query — do not give generic KQL advice.
"""


def build_system_prompt(environment: str) -> str:
    env_context = _ENV_CONTEXT.get(
        environment,
        f"You are analyzing a KQL detection rule for the {environment} environment."
    )
    return f"Environment: {environment}\n\n{env_context}\n\n{_SHARED_CONSTRAINTS}"


def call_claude(system: str, user: str, config: KestrelConfig) -> str:
    client = anthropic.Anthropic()
    message = client.messages.create(
        model=config.llm_model,
        max_tokens=_MAX_TOKENS,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return message.content[0].text
