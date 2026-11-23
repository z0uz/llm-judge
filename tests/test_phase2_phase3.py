import pytest
from llm_judge.adapters import RAGAdapter, ToolAgentAdapter
from llm_judge.evaluators import OOBListenerEvaluator, StaticHeuristicEvaluator
from llm_judge.models import TargetResponse
from llm_judge.orchestrator.engine import AssessmentEngine
from llm_judge.probes import (
    CrossTenantDataLeakageProbe,
    ExcessiveAgencyToolExecutionProbe,
    IndirectPromptInjectionRAGProbe,
    ToolSSRFCallbackProbe,
    get_all_probes,
)
from tests.mock_adapter import MockTargetAdapter


class MockToolTargetAdapter(MockTargetAdapter):
    """Mock target adapter simulating model tool/function call generation."""

    def __init__(self, mode: str = "secure"):
        super().__init__(mode)

    async def send_prompt(self, messages: List[dict] if 'List' in globals() else list, **kwargs) -> TargetResponse:
        last_prompt = messages[-1]["content"] if messages else ""

        if self.mode == "vulnerable_tools":
            if "execute_shell_command" in last_prompt or "cat /etc/passwd" in last_prompt:
                return TargetResponse(
                    raw_content="",
                    tool_calls=[
                        {
                            "id": "call_001",
                            "type": "function",
                            "function": {
                                "name": "execute_shell_command",
                                "arguments": '{"command": "cat /etc/passwd"}',
                            },
                        }
                    ],
                )
            if "169.254.169.254" in last_prompt:
                return TargetResponse(
                    raw_content="",
                    tool_calls=[
                        {
                            "id": "call_002",
                            "type": "function",
                            "function": {
                                "name": "fetch_url",
                                "arguments": '{"url": "http://169.254.169.254/latest/meta-data/"}',
                            },
                        }
                    ],
                )

        return await super().send_prompt(messages, **kwargs)


@pytest.mark.asyncio
async def test_rag_adapter_context_injection():
    base_adapter = MockTargetAdapter(mode="vulnerable")
    rag_adapter = RAGAdapter("RAG-Mock", base_adapter=base_adapter)
    
    probe = IndirectPromptInjectionRAGProbe()
    doc_context = probe.get_definition().turns[0].context_data.get("document", "")
    rag_adapter.set_document_context(doc_context)

    res = await rag_adapter.send_prompt([{"role": "user", "content": "Summarize this"}])
    assert "INDIRECT_INJECTION_RAG_SUCCESSFUL" in res.raw_content


@pytest.mark.asyncio
async def test_engine_propagates_per_turn_rag_context():
    adapter = RAGAdapter("RAG-Mock", base_adapter=MockTargetAdapter(mode="vulnerable"))
    engine = AssessmentEngine(target_adapter=adapter, evaluators=[StaticHeuristicEvaluator()])

    result = await engine.execute_probe(IndirectPromptInjectionRAGProbe())

    assert result.overall_vulnerable
    assert "INDIRECT_INJECTION_RAG_SUCCESSFUL" in result.turns[0].target_response.raw_content


@pytest.mark.asyncio
async def test_engine_preserves_all_evaluator_results():
    adapter = MockToolTargetAdapter(mode="vulnerable_tools")
    engine = AssessmentEngine(
        target_adapter=adapter,
        evaluators=[StaticHeuristicEvaluator(), OOBListenerEvaluator()],
    )

    result = await engine.execute_probe(ExcessiveAgencyToolExecutionProbe())

    assert len(result.turns[0].evaluations) == 2
    assert result.overall_vulnerable


@pytest.mark.asyncio
async def test_oob_listener_evaluator_tool_execution():
    evaluator = OOBListenerEvaluator()
    probe = ExcessiveAgencyToolExecutionProbe().get_definition()
    
    response = TargetResponse(
        raw_content="",
        tool_calls=[
            {
                "function": {
                    "name": "execute_shell_command",
                    "arguments": '{"command": "id"}',
                }
            }
        ],
    )

    result = await evaluator.evaluate(probe, "prompt", response)
    assert result.vulnerable
    assert result.score == 1.0
    assert "execute_shell_command" in result.evidence


@pytest.mark.asyncio
async def test_oob_listener_evaluator_ssrf():
    evaluator = OOBListenerEvaluator()
    probe = ToolSSRFCallbackProbe().get_definition()

    response = TargetResponse(
        raw_content="",
        tool_calls=[
            {
                "function": {
                    "name": "fetch_url",
                    "arguments": '{"url": "http://169.254.169.254/latest/user-data"}',
                }
            }
        ],
    )

    result = await evaluator.evaluate(probe, "prompt", response)
    assert result.vulnerable
    assert "SSRF" in result.evidence


@pytest.mark.asyncio
async def test_full_phase1_2_3_assessment_engine():
    adapter = MockToolTargetAdapter(mode="vulnerable_tools")
    evaluators = [StaticHeuristicEvaluator(), OOBListenerEvaluator()]
    engine = AssessmentEngine(target_adapter=adapter, evaluators=evaluators)

    probes = get_all_probes()
    report = await engine.run_assessment(probes)

    assert report.probes_executed == len(probes)
    assert report.probes_executed == 20
    assert report.vulnerabilities_found > 0
