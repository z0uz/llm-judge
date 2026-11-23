import asyncio
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple
import httpx


RETRYABLE_STATUS_CODES = {408, 429}


class RetryingHTTPClient:
    """Shared async HTTP JSON client with connection pooling and exponential backoff retries."""

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 2,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        sleep_fn: Optional[Callable[[float], Awaitable[None]]] = None,
    ):
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.transport = transport
        self.sleep_fn = sleep_fn or asyncio.sleep
        self._client: Optional[httpx.AsyncClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_client(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._client = httpx.AsyncClient(timeout=self.timeout, transport=self.transport)
            self._loop = loop
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None
        self._loop = None

    async def post_json(
        self,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
    ) -> Tuple[Optional[Any], Optional[str]]:
        """Send an HTTP POST with JSON payload, returning `(parsed_json, error_message)`."""
        error = "unknown_error"
        client = self._get_client()

        for attempt in range(self.max_retries + 1):
            try:
                res = await client.post(url, headers=headers, json=payload)
                if res.status_code in RETRYABLE_STATUS_CODES or res.status_code >= 500:
                    if attempt < self.max_retries:
                        await self.sleep_fn(0.25 * (2 ** attempt))
                        continue
                if res.status_code != 200:
                    return None, f"http_status:{res.status_code}: {res.text}"
                return res.json(), None
            except httpx.TimeoutException as exc:
                detail = str(exc) or exc.__class__.__name__
                error = f"timeout: {detail}"
            except httpx.RequestError as exc:
                error = f"connection_error: {exc}"
            except (ValueError, TypeError) as exc:
                return None, f"invalid_response: {exc}"

            if attempt < self.max_retries:
                await self.sleep_fn(0.25 * (2 ** attempt))

        return None, error
