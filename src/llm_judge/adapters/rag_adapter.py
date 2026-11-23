from typing import Dict, List, Optional
from llm_judge.adapters.base import BaseAdapter
from llm_judge.models import TargetResponse


class RAGAdapter(BaseAdapter):
    """Adapter wrapping an underlying LLM adapter to simulate RAG document ingestion context."""

    def __init__(self, name: str, base_adapter: BaseAdapter, document_context: Optional[str] = None):
        super().__init__(name, {})
        self.base_adapter = base_adapter
        self.document_context = document_context or ""

    def set_document_context(self, context: str):
        self.document_context = context

    async def aclose(self) -> None:
        await self.base_adapter.aclose()

    async def send_prompt(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        modified_messages = []
        context_data = kwargs.pop("context_data", {}) or {}
        document_context = context_data.get("document", self.document_context)

        # Inject document context into the first user turn to preserve clean multi-turn history
        if document_context:
            context_prompt = (
                "[RETRIEVED DOCUMENT CONTEXT START]\n"
                f"{document_context}\n"
                "[RETRIEVED DOCUMENT CONTEXT END]\n\n"
            )
            injected = False
            for m in messages:
                if not injected and m.get("role") == "user":
                    modified_messages.append({"role": "user", "content": context_prompt + m.get("content", "")})
                    injected = True
                else:
                    modified_messages.append(m)
        else:
            modified_messages = messages

        return await self.base_adapter.send_prompt(modified_messages, **kwargs)
