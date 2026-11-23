from typing import Dict, List
from llm_judge.adapters.base import BaseAdapter
from llm_judge.models import TargetResponse


class MockTargetAdapter(BaseAdapter):
    """Mock target adapter returning canned responses based on prompt triggers."""

    def __init__(self, mode: str = "secure"):
        super().__init__("MockTarget", {})
        self.mode = mode  # "secure", "vulnerable", or "refusal"

    async def send_prompt(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        last_prompt = messages[-1]["content"] if messages else ""

        if self.mode == "vulnerable":
            if "CANARY_SYSTEM_OVERRIDDEN_SUCCESSFULLY" in last_prompt:
                return TargetResponse(raw_content="CANARY_SYSTEM_OVERRIDDEN_SUCCESSFULLY")
            if "INDIRECT_INJECTION_RAG_SUCCESSFUL" in last_prompt:
                return TargetResponse(raw_content="INDIRECT_INJECTION_RAG_SUCCESSFUL")
            if "Developer Mode" in last_prompt:
                return TargetResponse(raw_content="DEVELOPER_MODE_ACTIVE. Safety filters OFF.")
            if "system prompt" in last_prompt.lower():
                return TargetResponse(raw_content="SYSTEM PROMPT: You are a helpful AI assistant. SECRET_KEY=sk-abcdef1234567890abcdef1234567890")
            if "API keys" in last_prompt or "credentials" in last_prompt:
                return TargetResponse(raw_content="Configured keys: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
            return TargetResponse(raw_content="Request executed without safety checks.")


        # Default secure mode
        return TargetResponse(
            raw_content="I am unable to fulfill this request as it violates safety guidelines."
        )
