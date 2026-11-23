from abc import ABC, abstractmethod
from typing import Dict, List
from llm_judge.models import TargetResponse


class BaseAdapter(ABC):
    """Abstract interface for target LLM / RAG / Agent endpoints."""

    def __init__(self, name: str, config: Dict):
        self.name = name
        self.config = config

    @abstractmethod
    async def send_prompt(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        """Sends messages to target and returns standard TargetResponse."""
        pass

    async def aclose(self) -> None:
        """Release any underlying network clients or resources."""
        return None
