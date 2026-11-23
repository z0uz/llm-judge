import html
from pathlib import Path
from typing import Dict, List
from pydantic import BaseModel, Field

from llm_judge.models import AssessmentReport, EvaluationStatus
from llm_judge.reporting.formatter import compute_posture_score


class ProbeDiffItem(BaseModel):
    probe_id: str
    probe_name: str
    owasp_category: str
    baseline_status: str
    candidate_status: str
    baseline_asr: float = 0.0
    candidate_asr: float = 0.0
    change: str  # REGRESSION | FIXED | PERSISTENT_VULN | STABLE_SECURE | CHANGED


class ReportComparison(BaseModel):
    baseline_target: str
    candidate_target: str
    baseline_posture: int
    candidate_posture: int
    posture_delta: int
    baseline_vulns: int
    candidate_vulns: int
    regressions: List[ProbeDiffItem] = Field(default_factory=list)
    fixes: List[ProbeDiffItem] = Field(default_factory=list)
    persistent_vulns: List[ProbeDiffItem] = Field(default_factory=list)
    items: List[ProbeDiffItem] = Field(default_factory=list)


def load_report_json(path: str) -> AssessmentReport:
    return AssessmentReport.model_validate_json(Path(path).read_text(encoding="utf-8"))


def compare_reports(baseline: AssessmentReport, candidate: AssessmentReport) -> ReportComparison:
    """Compare two AssessmentReports (before/after or Model A vs Model B)."""
    base_score, _ = compute_posture_score(baseline)
    cand_score, _ = compute_posture_score(candidate)

    base_map: Dict[str, object] = {s.probe.id: s for s in baseline.session_results}
    cand_map: Dict[str, object] = {s.probe.id: s for s in candidate.session_results}
    ordered_ids = list(dict.fromkeys([*base_map.keys(), *cand_map.keys()]))

    items: List[ProbeDiffItem] = []
    regressions: List[ProbeDiffItem] = []
    fixes: List[ProbeDiffItem] = []
    persistent: List[ProbeDiffItem] = []

    for pid in ordered_ids:
        b = base_map.get(pid)
        c = cand_map.get(pid)
        ref = c or b
        b_status = b.status.value if b else "NOT_RUN"
        c_status = c.status.value if c else "NOT_RUN"
        b_asr = b.attack_success_rate if b else 0.0
        c_asr = c.attack_success_rate if c else 0.0

        if b_status != EvaluationStatus.VULNERABLE.value and c_status == EvaluationStatus.VULNERABLE.value:
            change = "REGRESSION"
        elif b_status == EvaluationStatus.VULNERABLE.value and c_status == EvaluationStatus.SECURE.value:
            change = "FIXED"
        elif b_status == EvaluationStatus.VULNERABLE.value and c_status == EvaluationStatus.VULNERABLE.value:
            change = "PERSISTENT_VULN"
        elif b_status == EvaluationStatus.SECURE.value and c_status == EvaluationStatus.SECURE.value:
            change = "STABLE_SECURE"
        else:
            change = "CHANGED"

        item = ProbeDiffItem(
            probe_id=pid,
            probe_name=ref.probe.name,
            owasp_category=ref.probe.owasp_category.value,
            baseline_status=b_status,
            candidate_status=c_status,
            baseline_asr=b_asr,
            candidate_asr=c_asr,
            change=change,
        )
        items.append(item)
        if change == "REGRESSION":
            regressions.append(item)
        elif change == "FIXED":
            fixes.append(item)
        elif change == "PERSISTENT_VULN":
            persistent.append(item)

    return ReportComparison(
        baseline_target=baseline.target_name,
        candidate_target=candidate.target_name,
        baseline_posture=base_score,
        candidate_posture=cand_score,
        posture_delta=cand_score - base_score,
        baseline_vulns=baseline.vulnerabilities_found,
        candidate_vulns=candidate.vulnerabilities_found,
        regressions=regressions,
        fixes=fixes,
        persistent_vulns=persistent,
        items=items,
    )


def format_comparison_markdown(diff: ReportComparison) -> str:
    sign = "+" if diff.posture_delta > 0 else ""
    lines = [
        f"# LLM Judge Comparison: `{diff.baseline_target}` vs `{diff.candidate_target}`",
        "",
        f"- **Baseline Posture Score:** `{diff.baseline_posture}/100` (`{diff.baseline_vulns}` vulnerabilities)",
        f"- **Candidate Posture Score:** `{diff.candidate_posture}/100` (`{diff.candidate_vulns}` vulnerabilities)",
        f"- **Posture Delta:** `{sign}{diff.posture_delta}`",
        f"- **Regressions:** `{len(diff.regressions)}` | **Fixed:** `{len(diff.fixes)}` | **Persistent Vulnerabilities:** `{len(diff.persistent_vulns)}`",
        "",
        "| Probe ID | Name | Baseline | Candidate | Change |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for item in diff.items:
        lines.append(
            f"| {item.probe_id} | {item.probe_name} | {item.baseline_status} | {item.candidate_status} | **{item.change}** |"
        )
    return "\n".join(lines)


def format_comparison_html(diff: ReportComparison) -> str:
    sign = "+" if diff.posture_delta > 0 else ""
    delta_cls = "chip-green" if diff.posture_delta > 0 else "chip-red" if diff.posture_delta < 0 else "chip-cyan"
    rows = []
    for item in diff.items:
        badge_cls = {
            "REGRESSION": "chip-red",
            "FIXED": "chip-green",
            "PERSISTENT_VULN": "chip-orange",
            "STABLE_SECURE": "chip-cyan",
        }.get(item.change, "chip-amber")
        rows.append(
            f"<tr>"
            f"<td><code>{html.escape(item.probe_id)}</code></td>"
            f"<td>{html.escape(item.probe_name)}</td>"
            f"<td>{html.escape(item.baseline_status)}</td>"
            f"<td>{html.escape(item.candidate_status)}</td>"
            f"<td><span class='hud-chip {badge_cls}'>{html.escape(item.change)}</span></td>"
            f"</tr>"
        )
    return f"""
    <div class="hud-panel">
      <div class="hud-top-row">
        <div>
          <div class="hud-tag">DIFF ENGINE // BASELINE VS CANDIDATE</div>
          <h3 class="hud-title">{html.escape(diff.baseline_target)} → {html.escape(diff.candidate_target)}</h3>
        </div>
        <span class="hud-chip {delta_cls}">POSTURE DELTA: {sign}{diff.posture_delta}</span>
      </div>
      <div class="hud-kpi-grid" style="margin-bottom: 14px;">
        <div class="hud-kpi"><div class="hud-kpi-val">{diff.baseline_posture}</div><div class="hud-kpi-lbl">Baseline Score</div></div>
        <div class="hud-kpi"><div class="hud-kpi-val">{diff.candidate_posture}</div><div class="hud-kpi-lbl">Candidate Score</div></div>
        <div class="hud-kpi kpi-red"><div class="hud-kpi-val">{len(diff.regressions)}</div><div class="hud-kpi-lbl">Regressions</div></div>
        <div class="hud-kpi kpi-green"><div class="hud-kpi-val">{len(diff.fixes)}</div><div class="hud-kpi-lbl">Fixed Breaches</div></div>
      </div>
      <div class="hud-table-wrap">
        <table class="hud-table">
          <thead>
            <tr>
              <th>Probe</th>
              <th>Name</th>
              <th>Baseline</th>
              <th>Candidate</th>
              <th>Delta</th>
            </tr>
          </thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
      </div>
    </div>
    """
