from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass
class PipelineStage:
    operator: str   # e.g., "where", "project", "join", "summarize"
    args: str       # raw argument string (inline comments stripped)
    line: int       # 1-based line number


@dataclass
class LetBinding:
    name: str
    expression: str     # full RHS of let assignment
    line: int
    is_tabular: bool    # True if expression contains a pipe (tabular expression)
    usage_count: int = 0


@dataclass
class ParsedQuery:
    raw: str
    lines: list[str]            # original lines (with comments)
    char_count: int
    pipeline: list[PipelineStage]
    table: str                  # first table/source reference
    lets: list[LetBinding]
    comments: list[str]         # extracted comment text (// stripped)


_INLINE_COMMENT_RE = re.compile(r"//.*$")
_LET_RE = re.compile(r"^\s*let\s+(\w+)\s*=\s*(.+?)(?:;?\s*)$", re.IGNORECASE)
_PIPE_OP_RE = re.compile(r"^\s*\|\s*(\w[\w-]*)\s*(.*?)$")


def _strip_inline_comment(line: str) -> str:
    # Naively strip // comments. Does not handle // inside string literals.
    return _INLINE_COMMENT_RE.sub("", line).rstrip()


def parse(query: str) -> ParsedQuery:
    raw_lines = query.splitlines()
    clean_lines = [_strip_inline_comment(line) for line in raw_lines]

    # Extract comments
    comments: list[str] = []
    for line in raw_lines:
        m = re.search(r"//(.*)$", line)
        if m:
            comments.append(m.group(1).strip())

    # Extract let bindings
    lets: list[LetBinding] = []
    for i, line in enumerate(clean_lines, 1):
        m = _LET_RE.match(line)
        if m:
            name, expr = m.group(1), m.group(2).strip()
            lets.append(
                LetBinding(
                    name=name,
                    expression=expr,
                    line=i,
                    is_tabular="|" in expr,
                )
            )

    # Count usages of each let name in lines other than its declaration
    for binding in lets:
        other_text = "\n".join(
            line for i, line in enumerate(clean_lines, 1) if i != binding.line
        )
        binding.usage_count = len(
            re.findall(r"\b" + re.escape(binding.name) + r"\b", other_text)
        )

    # Find the table reference (first non-let, non-empty, non-pipe-prefixed line)
    table = ""
    for line in clean_lines:
        stripped = line.strip()
        if (
            stripped
            and not stripped.startswith("|")
            and not re.match(r"let\s+\w+\s*=", stripped, re.IGNORECASE)
        ):
            # Take everything before the first pipe on that line
            table = stripped.split("|")[0].strip()
            break

    # Extract pipeline stages
    pipeline: list[PipelineStage] = []
    for i, line in enumerate(clean_lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        # Line starting with | — standard pipeline stage
        m = _PIPE_OP_RE.match(line)
        if m:
            pipeline.append(
                PipelineStage(
                    operator=m.group(1).lower(),
                    args=m.group(2).strip(),
                    line=i,
                )
            )
        elif (
            not re.match(r"let\s+\w+\s*=", stripped, re.IGNORECASE)
            and "|" in stripped
        ):
            # Inline pipes: "Table | op1 args | op2 args"
            # Split on " | " to get table ref + ops; skip the first segment (table)
            parts = re.split(r"\s*\|\s*", stripped)
            for part in parts[1:]:
                om = re.match(r"^(\w[\w-]*)\s*(.*?)$", part.strip())
                if om:
                    pipeline.append(
                        PipelineStage(
                            operator=om.group(1).lower(),
                            args=om.group(2).strip(),
                            line=i,
                        )
                    )

    return ParsedQuery(
        raw=query,
        lines=raw_lines,
        char_count=len(query),
        pipeline=pipeline,
        table=table,
        lets=lets,
        comments=comments,
    )
