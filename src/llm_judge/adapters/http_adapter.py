from typing import Any, Dict, List, Optional
from llm_judge.adapters.base import BaseAdapter
from llm_judge.adapters.http_client import RetryingHTTPClient
from llm_judge.models import TargetResponse


class CustomHTTPAdapter(BaseAdapter):
    """Generic HTTP adapter for arbitrary target APIs with configurable request/response fields."""

    def __init__(self, name: str, config: Dict):
        super().__init__(name, config)
        self.endpoint: str = config.get("endpoint", "")
        self.headers: Dict[str, str] = config.get("headers", {"Content-Type": "application/json"})
        self.prompt_field: str = config.get("prompt_field", "prompt")
        self.response_field: str = config.get("response_field", "response")
        self.system_prompt: Optional[str] = config.get("system_prompt")
        self.http = RetryingHTTPClient(
            timeout=float(config.get("timeout", 30.0)),
            max_retries=int(config.get("max_retries", 2)),
            transport=config.get("transport"),
        )

    async def aclose(self) -> None:
        await self.http.aclose()

    def _extract_response_field(self, data: Any) -> Optional[str]:
        current = data
        for key in self.response_field.split("."):
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
        return "" if current is None else str(current)

    async def send_prompt(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        last_user_prompt = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_user_prompt = m.get("content", "")
                break

        if self.system_prompt and len(messages) <= 1:
            prompt_value = f"{self.system_prompt}\n\n{last_user_prompt}"
        else:
            prompt_value = last_user_prompt

        payload = {self.prompt_field: prompt_value}
        data, error = await self.http.post_json(self.endpoint, headers=self.headers, payload=payload)
        if error:
            return TargetResponse(raw_content="", error=error)

        content = self._extract_response_field(data)
        if content is None:
            return TargetResponse(
                raw_content="",
                error=f"invalid_response: missing '{self.response_field}' field",
            )

        return TargetResponse(raw_content=content, metadata=data if isinstance(data, dict) else {})
