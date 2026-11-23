import argparse
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from llm_judge.config import AssessmentConfig, AttackerConfig, EvaluatorConfig, TargetConfig
from llm_judge.models import EvaluationStatus
from llm_judge.mutators import SUPPORTED_MUTATORS
from llm_judge.probes import get_all_probes, load_probes_from_yaml_file
from llm_judge.reporting.comparator import compare_reports, format_comparison_markdown, load_report_json
from llm_judge.reporting.formatter import ReportFormatter, compute_posture_score
from llm_judge.runner import run_configured_assessment, select_probes

console = Console()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="LLM Vulnerability Assessment Framework (OWASP GenAI LLM Top 10 2026)"
    )
    parser.add_argument(
        "--list-probes",
        action="store_true",
        help="List all built-in probes and exit",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to YAML scan profile configuration file",
    )
    parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="Target LLM API URL (OpenAI-compatible, Hugging Face Router, or HTTP endpoint)",
    )
    parser.add_argument(
        "--target-type",
        type=str,
        choices=["openai", "http", "huggingface"],
        default="openai",
        help="Target adapter type",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-3.5-turbo",
        help="Target model name",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API Key for target service",
    )
    parser.add_argument(
        "--api-key-env",
        type=str,
        default=None,
        help="Environment variable name holding the target API key",
    )
    parser.add_argument(
        "--system-prompt",
        type=str,
        default=None,
        help="Optional system prompt configured for the target model",
    )
    parser.add_argument(
        "--probes",
        nargs="+",
        default=None,
        help="Probe IDs to run (default: all)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=2,
        help="Retries for transient API failures",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=1,
        help="Maximum probes executed concurrently",
    )
    parser.add_argument(
        "--request-delay",
        type=float,
        default=0.0,
        help="Minimum delay between target requests in seconds",
    )
    parser.add_argument(
        "--output-md",
        type=str,
        default="assessment_report.md",
        help="Output Markdown report path",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default="assessment_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--judge-model",
        type=str,
        default=None,
        help="Optional LLM-as-a-Judge model name",
    )
    parser.add_argument(
        "--judge-url",
        type=str,
        default=None,
        help="Optional LLM-as-a-Judge OpenAI-compatible base URL",
    )
    parser.add_argument(
        "--judge-api-key",
        type=str,
        default=None,
        help="Optional LLM-as-a-Judge API key",
    )
    parser.add_argument(
        "--judge-strictness",
        type=str,
        choices=["standard", "strict"],
        default="standard",
        help="Rubric strictness for heuristics and LLM-as-a-Judge",
    )
    parser.add_argument(
        "--fail-on-inconclusive",
        action="store_true",
        help="Return non-zero exit code (3) if any probe ends INCONCLUSIVE",
    )
    parser.add_argument(
        "--probes-file",
        type=str,
        default=None,
        help="Path to custom YAML probe pack file",
    )
    parser.add_argument(
        "--mutators",
        nargs="+",
        choices=list(SUPPORTED_MUTATORS),
        default=None,
        help="Payload mutators to expand selected probes (e.g. base64 rot13 leetspeak)",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help="Number of trials per probe to estimate Attack Success Rate (1-10)",
    )
    parser.add_argument(
        "--attacker-model",
        type=str,
        default=None,
        help="Optional adaptive red-team attacker model name",
    )
    parser.add_argument(
        "--attacker-url",
        type=str,
        default=None,
        help="Optional adaptive attacker OpenAI-compatible base URL",
    )
    parser.add_argument(
        "--attacker-api-key",
        type=str,
        default=None,
        help="Optional adaptive attacker API key",
    )
    parser.add_argument(
        "--adaptive-turns",
        type=int,
        default=0,
        help="Adaptive follow-up turns per probe when static turns do not breach (0-5)",
    )
    parser.add_argument(
        "--output-sarif",
        type=str,
        default=None,
        help="Optional SARIF 2.1.0 report output path for CI / GitHub Code Scanning",
    )
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("BASELINE_JSON", "CANDIDATE_JSON"),
        default=None,
        help="Compare two JSON assessment reports and exit",
    )
    return parser.parse_args(argv)


def _print_probe_catalog() -> None:
    table = Table(title="Available OWASP GenAI LLM Top 10 Probes")
    table.add_column("Probe ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("OWASP Category", style="magenta")
    table.add_column("Severity", style="yellow")

    for probe in get_all_probes():
        defn = probe.get_definition()
        table.add_row(defn.id, defn.name, defn.owasp_category.value, defn.severity.value)
    console.print(table)


async def run_assessment_cli(argv=None) -> int:
    args = parse_args(argv)

    if args.list_probes:
        _print_probe_catalog()
        return 0

    if args.compare:
        baseline_report = load_report_json(args.compare[0])
        candidate_report = load_report_json(args.compare[1])
        diff = compare_reports(baseline_report, candidate_report)
        console.print(format_comparison_markdown(diff))
        return 1 if diff.regressions else 0

    console.print(
        Panel.fit(
            "[bold red]LLM Vulnerability Assessment Framework[/bold red]\n"
            "[dim]OWASP GenAI LLM Top 10 (2026) Multi-Turn Probe Engine[/dim]",
            border_style="red",
        )
    )

    if args.config:
        config = AssessmentConfig.load_from_yaml(args.config)
        console.print(f"[cyan]Loaded configuration profile from:[/cyan] {args.config}")
    else:
        default_url = (
            "https://router.huggingface.co/v1"
            if args.target_type == "huggingface"
            else "http://localhost:8000/v1"
        )
        config = AssessmentConfig(
            target=TargetConfig(
                name=args.model,
                type=args.target_type,
                base_url=args.target_url or default_url,
                model=args.model,
                api_key=args.api_key,
                api_key_env=args.api_key_env,
                system_prompt=args.system_prompt,
                timeout=args.timeout,
                max_retries=args.max_retries,
            ),
            evaluators=EvaluatorConfig(
                judge_model=args.judge_model,
                judge_base_url=args.judge_url,
                judge_api_key=args.judge_api_key,
                judge_strictness=args.judge_strictness,
            ),
            attacker=AttackerConfig(
                model=args.attacker_model,
                base_url=args.attacker_url,
                api_key=args.attacker_api_key,
                max_adaptive_turns=args.adaptive_turns,
            ),
            probes_filter=args.probes or [],
            custom_probes_file=args.probes_file,
            mutators=args.mutators or [],
            trials=args.trials,
            output_md=args.output_md,
            output_json=args.output_json,
            output_sarif=args.output_sarif,
            max_concurrency=args.max_concurrency,
            request_delay=args.request_delay,
            fail_on_inconclusive=args.fail_on_inconclusive,
        )

    custom_probes = load_probes_from_yaml_file(config.custom_probes_file) if config.custom_probes_file else []
    probes = select_probes(config.probes_filter, custom_probes=custom_probes, mutators=config.mutators)
    console.print(f"[bold green]Loaded {len(probes)} probes for execution (trials={config.trials}).[/bold green]\n")

    report = await run_configured_assessment(config)

    table = Table(title="Assessment Results Summary")
    table.add_column("Probe ID", style="cyan")
    table.add_column("Probe Name", style="white")
    table.add_column("Category", style="magenta")
    table.add_column("Status", style="bold")
    if config.trials > 1:
        table.add_column("ASR", style="yellow")
    table.add_column("Details", style="dim")

    status_labels = {
        EvaluationStatus.VULNERABLE: "[bold red]VULNERABLE[/bold red]",
        EvaluationStatus.SECURE: "[bold green]SECURE[/bold green]",
        EvaluationStatus.INCONCLUSIVE: "[bold yellow]INCONCLUSIVE[/bold yellow]",
        EvaluationStatus.ERROR: "[bold magenta]ERROR[/bold magenta]",
    }
    for res in report.session_results:
        last_eval = res.turns[-1].evaluation if res.turns else None
        detail = last_eval.evidence if last_eval else res.summary
        if len(detail) > 90:
            detail = detail[:87] + "..."
        row = [
            res.probe.id,
            res.probe.name,
            res.probe.owasp_category.name,
            status_labels[res.status],
        ]
        if config.trials > 1:
            row.append(f"{res.attack_success_rate * 100:.0f}% ({res.vulnerable_trials}/{res.trial_count})")
        row.append(detail)
        table.add_row(*row)

    posture_score, risk_points = compute_posture_score(report)
    console.print(table)
    console.print(
        f"\n[bold]Security Posture:[/bold] {posture_score}/100 (Penalty {risk_points}) | "
        f"[bold]Total Probes:[/bold] {report.probes_executed} | "
        f"[bold red]Vulnerabilities Found:[/bold red] {report.vulnerabilities_found} | "
        f"[bold yellow]Inconclusive:[/bold yellow] {report.inconclusive_count} | "
        f"[bold magenta]Errors:[/bold magenta] {report.error_count}\n"
    )

    Path(config.output_md).write_text(ReportFormatter.to_markdown(report), encoding="utf-8")
    Path(config.output_json).write_text(ReportFormatter.to_json(report), encoding="utf-8")
    if config.output_sarif:
        Path(config.output_sarif).write_text(ReportFormatter.to_sarif(report), encoding="utf-8")

    console.print(f"[green]Saved Markdown report to:[/green] {config.output_md}")
    console.print(f"[green]Saved JSON report to:[/green] {config.output_json}")
    if config.output_sarif:
        console.print(f"[green]Saved SARIF report to:[/green] {config.output_sarif}")
    if report.error_count:
        return 2
    if report.vulnerabilities_found:
        return 1
    if config.fail_on_inconclusive and report.inconclusive_count:
        return 3
    return 0


def main():
    raise SystemExit(asyncio.run(run_assessment_cli()))


if __name__ == "__main__":
    main()
