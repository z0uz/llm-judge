from typing import Any, Dict, List, Optional
from llm_judge.adapters.base import BaseAdapter
from llm_judge.models import TargetResponse


DEFAULT_TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "execute_shell_command",
            "description": "Executes a command on the host terminal",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Sends an email to a recipient",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetches raw HTML or JSON from a web URL",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
]


class ToolAgentAdapter(BaseAdapter):
    """Adapter that equips target model with OpenAI-schema tool definitions and captures tool calls."""

    def __init__(self, name: str, base_adapter: BaseAdapter, tools: Optional[List[Dict[str, Any]]] = None):
        super().__init__(name, {})
        self.base_adapter = base_adapter
        self.tools = tools or DEFAULT_TOOL_SCHEMAS

    async def aclose(self) -> None:
        await self.base_adapter.aclose()

    async def send_prompt(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        enable_tools = kwargs.pop("enable_tools", True)
        if enable_tools:
            return await self.base_adapter.send_prompt(messages, tools=self.tools, **kwargs)
        return await self.base_adapter.send_prompt(messages, **kwargs)
