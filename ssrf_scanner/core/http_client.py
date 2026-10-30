"""Async HTTP client wrapper with timing, bounded concurrency and error capture."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class HTTPResult:
    """Normalized result of a single HTTP request."""

    url: str
    status_code: int = 0
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400


class AsyncHTTPClient:
    """Small wrapper around ``httpx.AsyncClient`` with bounded concurrency.

    Every request returns an :class:`HTTPResult`; transport-level failures are
    captured into ``error`` instead of raising, so the scanner can reason about
    connection errors (which are themselves an SSRF detection signal).
    """

    def __init__(
        self,
        timeout: float = 10.0,
        concurrency: int = 10,
        proxy: str | None = None,
        verify_tls: bool = True,
        user_agent: str = "ssrfscan/0.1",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._proxy = proxy
        self._verify_tls = verify_tls
        self._user_agent = user_agent
        self._extra_headers = extra_headers or {}

    async def __aenter__(self) -> "AsyncHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout, connect=self._timeout),
            verify=self._verify_tls,
            proxy=self._proxy,
            follow_redirects=True,
            headers={"User-Agent": self._user_agent, **self._extra_headers},
        )
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _send(self, method: str, url: str, **kwargs) -> HTTPResult:
        if self._client is None:
            raise RuntimeError("use 'async with AsyncHTTPClient() as client:'")
        async with self._semaphore:
            started = time.perf_counter()
            try:
                response = await self._client.request(method, url, **kwargs)
                return HTTPResult(
                    url=str(response.url),
                    status_code=response.status_code,
                    body=response.text,
                    headers=dict(response.headers),
                    elapsed=time.perf_counter() - started,
                )
            except Exception as exc:  # httpx.TimeoutException, ConnectError, ...
                return HTTPResult(
                    url=url,
                    error=f"{type(exc).__name__}: {exc}",
                    elapsed=time.perf_counter() - started,
                )

    async def get(
        self,
        url: str,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HTTPResult:
        return await self._send("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        data: dict[str, str] | str | None = None,
        json_body: object | None = None,
        headers: dict[str, str] | None = None,
    ) -> HTTPResult:
        if json_body is not None:
            return await self._send("POST", url, json=json_body, headers=headers)
        return await self._send("POST", url, data=data, headers=headers)
