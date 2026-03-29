from __future__ import annotations
import dataclasses
from kestrel.core.models import Finding
from kestrel.core.parser import ParsedQuery
from kestrel.core.rules import Rule
from kestrel.environments.registry import Environment


class Engine:
    def __init__(
        self,
        rules: list[Rule],
        severity_overrides: dict[str, str] | None = None,
        disabled_rule_ids: set[str] | None = None,
    ) -> None:
        self.rules = rules
        self.severity_overrides = severity_overrides or {}
        self.disabled_rule_ids = disabled_rule_ids or set()

    def analyze(self, parsed: ParsedQuery, env: Environment) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if env.is_rule_disabled(rule.rule_id):
                continue
            if rule.rule_id in self.disabled_rule_ids:
                continue
            for finding in rule.check(parsed, env):
                if finding.rule_id in self.severity_overrides:
                    finding = dataclasses.replace(finding, severity=self.severity_overrides[finding.rule_id])
                findings.append(finding)
        return findings


def default_engine(
    severity_overrides: dict[str, str] | None = None,
    disabled_rule_ids: set[str] | None = None,
) -> Engine:
    """Return an Engine pre-loaded with all 39 built-in rules."""
    from kestrel.core.rules.performance import (
        ContainsInsteadOfHas, RegexWithoutPrefilter, SearchOrUnionStarPerf,
        FilterOnComputedColumn, NoEarlyProject, LetWithoutMaterialize,
        DuplicateTableScan, JoinWithoutHint, GraphMatchDeepPath,
        DcountWithoutToscalar, SerializeEarly, CaseInsensitiveOperator,
    )
    from kestrel.core.rules.correctness import (
        HasSemanticMismatch, JoinWithoutKind, NondeterministicLetWithoutMaterialize,
        MissingTimeFilterInSubquery, DeprecatedThreatIntelTable,
        SeriesDecomposeDefaultThreshold, StdevWithoutZeroGuard, ArgMaxWithoutTimeFilter,
    )
    from kestrel.core.rules.sentinel import (
        SearchOrUnionStar, QueryTooLong, AdxCrossClusterFunction,
        BagUnpackWithoutColumnIfExists, TimeGeneratedNotInOutput, RawTableInsteadOfAsim,
        NrtTopLevelTimeFilter, ContinuousJoinOrUnion, ContinuousUnsupportedOperator,
        MissingEntityIdentifier, TimestampFilteredInXdr,
    )
    from kestrel.core.rules.structure import (
        TimeFilterNotFirst, WhereNotOrderedBySelectivity, NoProjectBeforeJoin,
        HardcodedLiterals, PipelineOrderDeviation,
    )
    from kestrel.core.rules.documentation import (
        MissingMitreTag, MissingAuthorHeader, MissingDescription,
    )

    rules = [
        ContainsInsteadOfHas(), RegexWithoutPrefilter(), SearchOrUnionStarPerf(),
        FilterOnComputedColumn(), NoEarlyProject(), LetWithoutMaterialize(),
        DuplicateTableScan(), JoinWithoutHint(), GraphMatchDeepPath(),
        DcountWithoutToscalar(), SerializeEarly(), CaseInsensitiveOperator(),
        HasSemanticMismatch(), JoinWithoutKind(), NondeterministicLetWithoutMaterialize(),
        MissingTimeFilterInSubquery(), DeprecatedThreatIntelTable(),
        SeriesDecomposeDefaultThreshold(), StdevWithoutZeroGuard(), ArgMaxWithoutTimeFilter(),
        SearchOrUnionStar(), QueryTooLong(), AdxCrossClusterFunction(),
        BagUnpackWithoutColumnIfExists(), TimeGeneratedNotInOutput(), RawTableInsteadOfAsim(),
        NrtTopLevelTimeFilter(), ContinuousJoinOrUnion(), ContinuousUnsupportedOperator(),
        MissingEntityIdentifier(), TimestampFilteredInXdr(),
        TimeFilterNotFirst(), WhereNotOrderedBySelectivity(), NoProjectBeforeJoin(),
        HardcodedLiterals(), PipelineOrderDeviation(),
        MissingMitreTag(), MissingAuthorHeader(), MissingDescription(),
    ]
    return Engine(rules, severity_overrides=severity_overrides, disabled_rule_ids=disabled_rule_ids)
