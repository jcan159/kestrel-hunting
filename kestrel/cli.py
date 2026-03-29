from __future__ import annotations
import sys
import click
from kestrel import analyze, AnalysisConfig
from kestrel.output.formats import format_result


@click.group()
def main() -> None:
    """Kestrel — KQL detection rule analyzer."""


@main.command()
@click.argument("file", default="-")
@click.option("--env", "environment", default="sentinel-scheduled",
              help="Target environment (sentinel-scheduled, sentinel-nrt, defender-xdr, defender-xdr-continuous)")
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json", "markdown"]),
              help="Output format")
@click.option("--no-llm", is_flag=True, default=False, help="Disable LLM analysis (fast CI mode)")
@click.option("--min-score", "min_score", default=None, type=int,
              help="Fail with exit code 1 if overall score is below this threshold")
@click.option("--output", "outputs", multiple=True, default=("report",),
              help="LLM outputs to request: report, logic_review, tests, rewrite")
def analyze_cmd(
    file: str,
    environment: str,
    fmt: str,
    no_llm: bool,
    min_score: int | None,
    outputs: tuple[str, ...],
) -> None:
    """Analyze a KQL detection rule file (or - for stdin)."""
    try:
        if file == "-":
            query = click.get_text_stream("stdin").read()
            filename = None
        else:
            from pathlib import Path
            p = Path(file)
            query = p.read_text()
            filename = p.name

        cfg = AnalysisConfig(
            environment=environment,
            llm_enabled=not no_llm,
            outputs=list(outputs),
        )
        result = analyze(query, cfg)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(3)

    output = format_result(result, fmt=fmt, filename=filename)
    click.echo(output)

    has_errors = any(f.severity == "error" for f in result.findings)
    score_fail = min_score is not None and result.score.overall < min_score

    if has_errors or score_fail:
        sys.exit(1)
