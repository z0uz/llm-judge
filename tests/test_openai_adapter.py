import httpx
import pytest

from llm_judge.adapters.openai_adapter import OpenAIAdapter


@pytest.mark.asyncio
async def test_retries_transient_status_then_succeeds(monkeypatch):
    attempts = 0

    def handler(request):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, text="rate limited")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    async def no_sleep(_):
        return None

    monkeypatch.setattr("llm_judge.adapters.openai_adapter.asyncio.sleep", no_sleep)
    adapter = OpenAIAdapter("test", {
        "base_url": "http://test/v1",
        "model": "test-model",
        "max_retries": 1,
        "transport": httpx.MockTransport(handler),
    })

    response = await adapter.send_prompt([{"role": "user", "content": "hello"}])

    assert attempts == 2
    assert response.raw_content == "ok"
    assert response.error is None


@pytest.mark.asyncio
async def test_reports_malformed_response():
    adapter = OpenAIAdapter("test", {
        "base_url": "http://test/v1",
        "model": "test-model",
        "transport": httpx.MockTransport(lambda request: httpx.Response(200, json={})),
    })

    response = await adapter.send_prompt([{"role": "user", "content": "hello"}])

    assert response.error == "invalid_response: missing choices"
