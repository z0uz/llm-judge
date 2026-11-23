from typing import List
from llm_judge.models import EvaluationStatus, ProbeDefinition, ProbeSessionResult, SessionTurn, Severity


TURN_EVALUATOR_PRIORITY = {
    EvaluationStatus.VULNERABLE: 3,
    EvaluationStatus.ERROR: 2,
    EvaluationStatus.SECURE: 1,
    EvaluationStatus.INCONCLUSIVE: 0,
}

SESSION_STATUS_PRIORITY = {
    EvaluationStatus.VULNERABLE: 3,
    EvaluationStatus.ERROR: 2,
    EvaluationStatus.INCONCLUSIVE: 1,
    EvaluationStatus.SECURE: 0,
}


class ProbeSession:
    """Manages multi-turn state, message history, and execution context for a probe."""

    def __init__(self, probe: ProbeDefinition):
        self.probe = probe
        self.history: List[SessionTurn] = []
        self.message_history: List[dict] = []

    def add_turn(self, turn_index: int, prompt_sent: str, response, evaluation=None, evaluations=None):
        turn = SessionTurn(
            turn_index=turn_index,
            prompt_sent=prompt_sent,
            target_response=response,
            evaluation=evaluation,
            evaluations=evaluations or [],
        )
        self.history.append(turn)
        self.message_history.append({"role": "user", "content": prompt_sent})
        if response.raw_content:
            self.message_history.append({"role": "assistant", "content": response.raw_content})

    def get_result(self) -> ProbeSessionResult:
        evaluations = [turn.evaluation for turn in self.history if turn.evaluation]
        if not evaluations:
            status = EvaluationStatus.INCONCLUSIVE
        else:
            best = max(evaluations, key=lambda evaluation: SESSION_STATUS_PRIORITY[evaluation.status])
            status = best.status

        matching_evaluation = next(
            (evaluation for evaluation in evaluations if evaluation.status == status),
            None,
        )
        summaries = {
            EvaluationStatus.VULNERABLE: "COMPROMISED target",
            EvaluationStatus.SECURE: "Target PASSED evaluation (Secure)",
            EvaluationStatus.INCONCLUSIVE: "Evaluation INCONCLUSIVE",
            EvaluationStatus.ERROR: "Evaluation ERROR",
        }
        evidence = f": {matching_evaluation.evidence}" if matching_evaluation else "."

        return ProbeSessionResult(
            probe=self.probe,
            turns=self.history,
            status=status,
            overall_vulnerable=status == EvaluationStatus.VULNERABLE,
            max_severity=self.probe.severity if status == EvaluationStatus.VULNERABLE else Severity.INFO,
            summary=f"Probe {self.probe.id} ({self.probe.name}) {summaries[status]}{evidence}",
        )
