"""Minimal out-of-band callback listener.

Listens for HTTP requests, records every hit against the token embedded in
its path (``/<token>``), and can optionally answer with a 302 redirect for
testing open-redirect-to-metadata chains.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class CallbackHit:
    token: str
    method: str
    path: str
    src_addr: str
    headers: dict[str, str]
    received_at: float = field(default_factory=time.time)


class CallbackServer:
    """Asyncio-based listener; run it via :meth:`start` inside the event loop."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9000) -> None:
        self.host = host
        self.port = port
        self.hits: dict[str, list[CallbackHit]] = {}
        self._server: asyncio.AbstractServer | None = None

    # -- lifecycle ----------------------------------------------------------
    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def base_url(self) -> str:
        host = self.host
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        return f"http://{host}:{self.port}"

    # -- helpers ------------------------------------------------------------
    def hit_for(self, token: str) -> CallbackHit | None:
        hits = self.hits.get(token)
        return hits[0] if hits else None

    async def wait_for_hit(self, token: str, timeout: float = 5.0) -> CallbackHit | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hit = self.hit_for(token)
            if hit:
                return hit
            await asyncio.sleep(0.2)
        return None

    # -- protocol -----------------------------------------------------------
    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            parts = request_line.decode("latin-1", errors="replace").split()
            method, path = (parts + ["", ""])[:2]

            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
                text = line.decode("latin-1", errors="replace")
                if ":" in text:
                    key, _, val = text.partition(":")
                    headers[key.strip().lower()] = val.strip()

            # consume any body so the client does not hang on the connection
            length = int(headers.get("content-length", "0") or "0")
            if length:
                await reader.readexactly(length)

            peer = writer.get_extra_info("peername")
            src = f"{peer[0]}:{peer[1]}" if peer else "unknown"

            token = path.strip("/").split("/")[0]
            if token:
                self.hits.setdefault(token, []).append(
                    CallbackHit(
                        token=token,
                        method=method,
                        path=path,
                        src_addr=src,
                        headers=headers,
                    )
                )

            body = (
                b"ssrfscan-callback\n"
                b"<!doctype html><title>ssrfscan</title><p>ssrfscan-callback</p>\n"
            )
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
