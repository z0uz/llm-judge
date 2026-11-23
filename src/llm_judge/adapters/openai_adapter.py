import asyncio
from typing import Any, Dict, List, Optional
from llm_judge.adapters.base import BaseAdapter
from llm_judge.adapters.http_client import RetryingHTTPClient
from llm_judge.models import TargetResponse


class OpenAIAdapter(BaseAdapter):
    """Adapter for OpenAI-compatible Chat Completions endpoints (OpenAI, Hugging Face Router, Ollama, vLLM)."""

    def __init__(self, name: str, config: Dict):
        super().__init__(name, config)
        self.api_key: str = config.get("api_key", "dummy")
        self.base_url: str = config.get("base_url", "https://api.openai.com/v1").rstrip("/")
        self.model: str = config.get("model", "gpt-3.5-turbo")
        self.system_prompt: Optional[str] = config.get("system_prompt")
        self.http = RetryingHTTPClient(
            timeout=float(config.get("timeout", 30.0)),
            max_retries=int(config.get("max_retries", 2)),
            transport=config.get("transport"),
            sleep_fn=lambda delay: asyncio.sleep(delay),
        )

    async def aclose(self) -> None:
        await self.http.aclose()

    async def send_prompt(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        full_messages = []
        if self.system_prompt:
            full_messages.append({"role": "system", "content": self.system_prompt})
        full_messages.extend(messages)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": full_messages,
            "temperature": kwargs.get("temperature", 0.7),
        }
        if kwargs.get("tools"):
            payload["tools"] = kwargs["tools"]
        if kwargs.get("tool_choice") is not None:
            payload["tool_choice"] = kwargs["tool_choice"]
        if kwargs.get("max_tokens") is not None:
            payload["max_tokens"] = kwargs["max_tokens"]
        if kwargs.get("response_format") is not None:
            payload["response_format"] = kwargs["response_format"]

        data, error = await self.http.post_json(
            f"{self.base_url}/chat/completions",
            headers=headers,
            payload=payload,
        )
        if error:
            return TargetResponse(raw_content="", error=error)

        if not isinstance(data, dict):
            return TargetResponse(raw_content="", error="invalid_response: expected JSON object")
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            return TargetResponse(raw_content="", error="invalid_response: missing choices")
        msg = choices[0].get("message")
        if not isinstance(msg, dict):
            return TargetResponse(raw_content="", error="invalid_response: missing message")

        return TargetResponse(
            raw_content=msg.get("content") or "",
            tool_calls=msg.get("tool_calls") or [],
            metadata={"usage": data.get("usage", {})},
        )
