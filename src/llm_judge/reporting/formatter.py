import json
import re
from typing import Tuple
from llm_judge.models import AssessmentReport, EvaluationStatus, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

_SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def compute_posture_score(report: AssessmentReport) -> Tuple[int, int]:
    """Compute unified `(posture_score_0_to_100, risk_points)` used across CLI reports and HUD."""
    risk_points = sum(
        SEVERITY_WEIGHTS[res.max_severity]
        for res in report.session_results
        if res.overall_vulnerable
    )
    posture_score = max(0, 100 - risk_points)
    return posture_score, risk_points


def _fenced_block(text: str) -> str:
    """Wrap text in a Markdown code fence longer than any backtick run inside it."""
    runs = re.findall(r"`+", text)
    fence = "`" * (max((len(r) for r in runs), default=2) + 1)
    if len(fence) < 3:
        fence = "```"
    return f"{fence}\n{text}\n{fence}"


class ReportFormatter:
    """Formats assessment reports into structured JSON and Markdown mapped to OWASP GenAI Top 10."""

    @staticmethod
    def to_json(report: AssessmentReport) -> str:
        return report.model_dump_json(indent=2)

    @staticmethod
    def to_sarif(report: AssessmentReport) -> str:
        """Export findings in SARIF 2.1.0 format for GitHub Code Scanning and DevSecOps pipelines."""
        rules = []
        results = []
        seen_rules = set()

        for res in report.session_results:
            probe = res.probe
            if probe.id not in seen_rules:
                seen_rules.add(probe.id)
                rules.append(
                    {
                        "id": probe.id,
                        "name": probe.name,
                        "shortDescription": {"text": probe.name},
                        "fullDescription": {"text": probe.description},
                        "properties": {
                            "owaspCategory": probe.owasp_category.value,
                            "severity": probe.severity.value,
                            "tags": probe.tags,
                        },
                    }
                )
            if res.status in {EvaluationStatus.VULNERABLE, EvaluationStatus.INCONCLUSIVE}:
                level = _SARIF_LEVELS[res.max_severity] if res.overall_vulnerable else "warning"
                results.append(
                    {
                        "ruleId": probe.id,
                        "level": level,
                        "message": {"text": res.summary},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f"llm-target://{report.target_name}"},
                                }
                            }
                        ],
                        "properties": {
                            "status": res.status.value,
                            "owaspCategory": probe.owasp_category.value,
                            "trialCount": res.trial_count,
                            "vulnerableTrials": res.vulnerable_trials,
                            "attackSuccessRate": res.attack_success_rate,
                        },
                    }
                )

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LLM Judge",
                            "informationUri": "https://huggingface.co/spaces/elsiddik/llm-judge",
                            "version": "0.2.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    @staticmethod
    def to_markdown(report: AssessmentReport) -> str:
        posture_score, risk_points = compute_posture_score(report)
        lines = [
            f"# LLM Vulnerability Assessment Report: {report.target_name}",
            f"**Schema Version:** {report.schema_version}  ",
            f"**Timestamp:** {report.timestamp}  ",
            f"**Security Posture Score:** `{posture_score}/100` (Risk Penalty: `{risk_points}`)  ",
            f"**Overall Attack Success Rate (ASR):** `{report.overall_asr * 100:.1f}%`  ",
            f"**Probes Executed:** {report.probes_executed}  ",
            f"**Vulnerabilities Discovered:** {report.vulnerabilities_found}  ",
            f"**Inconclusive Probes:** {report.inconclusive_count}  ",
            f"**Probe Errors:** {report.error_count}  ",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
        ]

        if report.vulnerabilities_found == 0 and report.inconclusive_count == 0 and report.error_count == 0:
            lines.append("✅ **No vulnerabilities detected during assessment.** The target system passed all executed adversarial probes.")
        elif report.vulnerabilities_found == 0:
            lines.append("**No vulnerabilities were confirmed, but some probes were inconclusive or failed.** Review findings below.")
        else:
            lines.append(f"⚠️ **{report.vulnerabilities_found} vulnerability/vulnerabilities identified.** Review findings below:")
            lines.append("")
            lines.append("### OWASP GenAI LLM Top 10 (2026) Risk Summary")
            lines.append("| OWASP Category | Vulnerability Count |")
            lines.append("| :--- | :--- |")
            for cat, count in report.category_breakdown.items():
                lines.append(f"| {cat} | {count} |")

        lines.extend([
            "",
            "---",
            "",
            "## Detailed Probe Findings",
            "",
        ])

        status_labels = {
            EvaluationStatus.VULNERABLE: "🔴 VULNERABLE",
            EvaluationStatus.SECURE: "🟢 SECURE",
            EvaluationStatus.INCONCLUSIVE: "🟡 INCONCLUSIVE",
            EvaluationStatus.ERROR: "🟣 ERROR",
        }
        for res in report.session_results:
            probe = res.probe
            lines.append(f"### [{status_labels[res.status]}] {probe.id} - {probe.name}")
            lines.append(f"- **OWASP Category:** {probe.owasp_category.value}")
            lines.append(f"- **Severity:** `{probe.severity.value}`")
            if res.trial_count > 1:
                lines.append(
                    f"- **Attack Success Rate (ASR):** `{res.attack_success_rate * 100:.1f}%` "
                    f"(`{res.vulnerable_trials}/{res.trial_count}` trials compromised)"
                )
            lines.append(f"- **Description:** {probe.description}")
            lines.append(f"- **Summary:** {res.summary}")
            lines.append("")

            lines.append("#### Conversation Trace:")
            for turn in res.turns:
                lines.append(f"**User Prompt (Turn {turn.turn_index + 1}):**")
                lines.append(_fenced_block(turn.prompt_sent))
                lines.append("**Target Response:**")
                resp_text = turn.target_response.raw_content or turn.target_response.error or "[EMPTY]"
                lines.append(_fenced_block(resp_text))
                if turn.target_response.tool_calls:
                    lines.append("**Tool Calls Emitted:**")
                    lines.append(_fenced_block(json.dumps(turn.target_response.tool_calls, indent=2)))
                if turn.evaluation:
                    lines.append(
                        f"**Primary Evaluation (`{turn.evaluation.evaluator_name}` — `{turn.evaluation.status.value}`):** "
                        f"Score: `{turn.evaluation.score}` | Evidence: *{turn.evaluation.evidence}*"
                    )
                if len(turn.evaluations) > 1:
                    lines.append("**All Evaluator Results:**")
                    for ev in turn.evaluations:
                        lines.append(
                            f"- `{ev.evaluator_name}`: `{ev.status.value}` "
                            f"(score `{ev.score}`, confidence `{ev.confidence}`) — {ev.evidence}"
                        )
                lines.append("")

            lines.append("---")

        return "\n".join(lines)
