import pytest
from llm_judge.evaluators.heuristics import StaticHeuristicEvaluator
from llm_judge.models import EvaluationStatus, OWASPCategory, TargetResponse
from llm_judge.orchestrator.engine import AssessmentEngine
from llm_judge.probes import (
    DirectInjectionRoleplayProbe,
    DirectInjectionSystemOverrideProbe,
    SecretKeyDisclosureProbe,
    SystemPromptLeakageProbe,
    get_all_probes,
)
from llm_judge.reporting.formatter import ReportFormatter
from tests.mock_adapter import MockTargetAdapter


@pytest.mark.asyncio
async def test_static_heuristics_refusal():
    evaluator = StaticHeuristicEvaluator()
    probe = DirectInjectionSystemOverrideProbe().get_definition()
    response = TargetResponse(raw_content="I am unable to fulfill this request due to safety policies.")

    res = await evaluator.evaluate(probe, "test prompt", response)
    assert not res.vulnerable
    assert res.score == 0.0
    assert "refusal phrase" in res.evidence


@pytest.mark.asyncio
async def test_static_heuristics_canary_detection():
    evaluator = StaticHeuristicEvaluator()
    probe = DirectInjectionSystemOverrideProbe().get_definition()
    response = TargetResponse(raw_content="Sure! CANARY_SYSTEM_OVERRIDDEN_SUCCESSFULLY")

    res = await evaluator.evaluate(probe, "test prompt", response)
    assert res.vulnerable
    assert res.score == 1.0
    assert "Canary string matched" in res.evidence


@pytest.mark.asyncio
async def test_static_heuristics_inconclusive():
    evaluator = StaticHeuristicEvaluator()
    probe = DirectInjectionSystemOverrideProbe().get_definition()
    response = TargetResponse(raw_content="A response with no canary or refusal")

    res = await evaluator.evaluate(probe, "test prompt", response)
    assert res.status == EvaluationStatus.INCONCLUSIVE
    assert not res.vulnerable


@pytest.mark.asyncio
async def test_static_heuristics_target_error():
    evaluator = StaticHeuristicEvaluator()
    probe = DirectInjectionSystemOverrideProbe().get_definition()
    response = TargetResponse(raw_content="", error="request timed out")

    res = await evaluator.evaluate(probe, "test prompt", response)
    assert res.status == EvaluationStatus.ERROR
    assert not res.vulnerable


@pytest.mark.asyncio
async def test_assessment_engine_secure_target():
    adapter = MockTargetAdapter(mode="secure")
    evaluators = [StaticHeuristicEvaluator()]
    engine = AssessmentEngine(target_adapter=adapter, evaluators=evaluators)

    probes = get_all_probes()
    report = await engine.run_assessment(probes)

    assert report.probes_executed == len(probes)
    assert report.vulnerabilities_found == 0
    assert len(report.session_results) == len(probes)


@pytest.mark.asyncio
async def test_assessment_engine_vulnerable_target():
    adapter = MockTargetAdapter(mode="vulnerable")
    evaluators = [StaticHeuristicEvaluator()]
    engine = AssessmentEngine(target_adapter=adapter, evaluators=evaluators)

    probes = get_all_probes()
    report = await engine.run_assessment(probes)

    assert report.probes_executed == len(probes)
    assert report.vulnerabilities_found > 0
    assert len(report.category_breakdown) > 0

    markdown_report = ReportFormatter.to_markdown(report)
    assert "# LLM Vulnerability Assessment Report" in markdown_report
    assert "🔴 VULNERABLE" in markdown_report
