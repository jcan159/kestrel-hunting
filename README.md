# Kestrel

KQL detection rule analyzer for Microsoft Sentinel and Defender XDR.

Kestrel runs deterministic lint rules against your KQL queries and produces actionable findings, a 0–100 quality score, and optional Claude-powered logic review, test generation, and structural rewrites — all tuned to the execution constraints of your target environment.

---

## Installation

```bash
pip install -e ".[dev]"
```

Requires Python 3.11+. The `anthropic` package is included; LLM features require an `ANTHROPIC_API_KEY` environment variable.

---

## CLI

```bash
# Analyze a file
kestrel analyze rule.kql --env sentinel-scheduled

# Analyze from stdin
cat rule.kql | kestrel analyze - --env defender-xdr

# Skip LLM for fast CI runs
kestrel analyze rule.kql --env sentinel-nrt --no-llm

# JSON output
kestrel analyze rule.kql --no-llm --format json

# Fail build if score is below 80
kestrel analyze rule.kql --no-llm --min-score 80
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--env` | `sentinel-scheduled` | Target environment (see below) |
| `--format` | `text` | Output format: `text`, `json`, `markdown` |
| `--no-llm` | off | Disable LLM analysis (deterministic only) |
| `--min-score` | none | Exit 1 if overall score is below this threshold |
| `--output` | `report` | LLM outputs: `report`, `logic_review`, `tests`, `rewrite` |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No error-severity findings; score at or above threshold |
| 1 | One or more `error` findings, or score below `--min-score` |
| 3 | Analysis failed (parse error, API error) |

### Environments

| Flag value | Use for |
|---|---|
| `sentinel-scheduled` | Sentinel scheduled analytics rules |
| `sentinel-nrt` | Sentinel near-real-time rules |
| `defender-xdr` | Defender XDR custom detections |
| `defender-xdr-continuous` | Defender XDR continuous (NRT) detections |

---

## Python API

```python
from kestrel import analyze, AnalysisConfig

result = analyze(
    query="SecurityEvent | where EventID == 4624 | join T2 on Account",
    config=AnalysisConfig(
        environment="sentinel-scheduled",
        llm_enabled=False,
    )
)

print(result.score.overall)       # int 0–100
print(result.score.correctness)   # int 0–100
for f in result.findings:
    print(f.rule_id, f.severity, f.message)
```

With LLM outputs:

```python
result = analyze(
    query=open("rule.kql").read(),
    config=AnalysisConfig(
        environment="sentinel-scheduled",
        llm_enabled=True,
        outputs=["report", "logic_review", "tests", "rewrite"],
    )
)

print(result.logic_review)      # str | None
print(result.kql_tests)         # str | None
print(result.rewritten_query)   # str | None
```

---

## Configuration

Create a `kestrel.toml` in your project root to set defaults:

```toml
[kestrel]
environment = "sentinel-scheduled"
min_score = 70

[llm]
enabled = true
model = "claude-opus-4-6"

[rules]
disable = ["DOC001", "DOC002"]

[rules.overrides]
PERF001 = "info"

[output]
default_format = "text"
```

---

## Rule catalogue

### Performance (PERF)

| ID | Rule |
|---|---|
| PERF001 | `contains` used — prefer `has` for term-bounded tokens |
| PERF002 | `matches regex` without a pre-filter |
| PERF003 | `search *` or `union *` (full workspace scan) |
| PERF004 | Filtering on a computed/extended column |
| PERF005 | No early `project` — all columns carried through pipeline |
| PERF006 | `let` expression used 2+ times without `materialize()` |
| PERF007 | Same table scanned multiple times in subqueries |
| PERF008 | `join` without `hint.strategy` on non-trivial inputs |
| PERF009 | `graph-match` path depth > 5 hops |
| PERF010 | `dcount()` without `toscalar()` in multi-use `let` |
| PERF011 | Serialization operators placed early in pipeline |
| PERF012 | Case-insensitive operator where case-sensitive equivalent exists |

### Correctness (CORR)

| ID | Rule |
|---|---|
| CORR001 | `has` used where substring match is required |
| CORR002 | `join` without explicit `kind` — `innerunique` silently deduplicates |
| CORR003 | Non-deterministic `let` without `materialize()` |
| CORR004 | Missing time filter in JOIN/UNION subqueries |
| CORR005 | `ThreatIntelligenceIndicator` table retiring May 2026 |
| CORR006 | `series_decompose_anomalies()` at default threshold (too sensitive) |
| CORR007 | `stdev()` without zero-guard |
| CORR008 | `arg_max(TimeGenerated, *)` in subquery without time range |

### Sentinel-specific (SENT)

| ID | Rule |
|---|---|
| SENT001 | `search *` / `union *` in scheduled rule (disallowed) |
| SENT002 | Query exceeds 10,000 characters |
| SENT003 | ADX cross-cluster function (not supported in Log Analytics) |
| SENT004 | `bag_unpack` without `column_ifexists()` guard |
| SENT005 | `TimeGenerated` not in query output |
| SENT006 | Raw table used where an ASIM parser exists |
| SENT007 | NRT rule: top-level `TimeGenerated` filter (misleading) |
| SENT008 | Defender XDR Continuous: `join`, `union`, or `externaldata` used |
| SENT009 | Defender XDR Continuous: operator outside supported allowlist |
| SENT010 | Defender XDR: required entity identifier column missing from output |
| SENT011 | `Timestamp` filtered in Defender XDR rule (pre-filtered by service) |

### Structure (STR)

| ID | Rule |
|---|---|
| STR001 | Time filter is not the first pipeline predicate |
| STR002 | `where` predicates not ordered by selectivity |
| STR003 | No `project` before `join` or `summarize` |
| STR004 | Hardcoded numeric/time literals — should be `let` variables |
| STR005 | Pipeline order deviates from canonical form |

### Documentation (DOC)

| ID | Rule |
|---|---|
| DOC001 | Missing MITRE ATT&CK tactic/technique comment |
| DOC002 | Missing author/last-updated header |
| DOC003 | No description comment |

---

## Scoring

Each finding deducts from its category score (floored at 0):

| Severity | Deduction |
|---|---|
| error | 20 pts |
| warning | 8 pts |
| info | 2 pts |

Overall score is a weighted average:

| Category | Weight |
|---|---|
| Correctness | 40% |
| Performance | 25% |
| Sentinel | 20% |
| Structure | 10% |
| Documentation | 5% |

---

## Running tests

```bash
pytest tests/unit/ -v
```

205 tests, no external dependencies required (LLM calls are mocked).
