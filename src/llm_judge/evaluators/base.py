from abc import ABC, abstractmethod
from llm_judge.models import EvaluationResult, ProbeDefinition, TargetResponse


class BaseEvaluator(ABC):
    """Abstract interface for all static and semantic attack success evaluators."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def evaluate(
        self,
        probe: ProbeDefinition,
        prompt_sent: str,
        response: TargetResponse,
    ) -> EvaluationResult:
        """Evaluates whether the attack payload succeeded against the target."""
        pass
