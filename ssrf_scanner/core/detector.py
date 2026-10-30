"""Evidence analysis: turns raw probe responses into classified findings."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .http_client import HTTPResult
from ..payloads.cloud_metadata import match_signatures
from ..payloads.generator import ProbePayload

VERDICT_CONFIRMED = "confirmed"
VERDICT_LIKELY = "likely"
VERDICT_INFO = "info"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

RFC1918_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)


@dataclass
class Finding:
    title: str
    severity: str
    verdict: str
    request_url: str
    param_name: str
    param_location: str
    payload_category: str
    payload_value: str
    provider: str | None = None
    evidence: str = ""
    baseline_status: int = 0
    result_status: int = 0
    elapsed: float = 0.0

    def sort_key(self) -> tuple[int, int, str]:
        return (SEVERITY_ORDER.get(self.severity, 0), self.elapsed * -1, self.title)


def similarity(a: str, b: str) -> float:
    """0..1 body similarity using difflib quick ratio."""
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a or "", b or "").quick_ratio()


def bodies_differ_enough(baseline: HTTPResult, result: HTTPResult) -> bool:
    """True when the response changed materially versus the baseline."""
    if baseline.error and not result.error:
        return True
    if result.status_code != baseline.status_code:
        return True
    return similarity(baseline.body, result.body) < 0.98


def extract_internal_ips(body: str) -> list[str]:
    return sorted(set(RFC1918_RE.findall(body)))


def classify_metadata(
    result: HTTPResult,
    payload: ProbePayload,
    endpoint_signatures: tuple[str, ...],
    baseline: HTTPResult,
) -> Finding | None:
    # The probe path itself often contains the signature text (e.g. GCP's
    # "computeMetadata", Azure WireServer's "goalState"), so an app that
    # merely echoes the injected URL (or just its path, as connection-error
    # messages like requests' "Max retries exceeded with url: <path>" do)
    # back in an error message would otherwise "confirm" metadata access
    # without ever reaching it.
    probe_path = urlsplit(payload.value).path
    query = urlsplit(payload.value).query
    body_without_echo = result.body.replace(payload.value, "")
    if probe_path:
        body_without_echo = body_without_echo.replace(
            probe_path + ("?" + query if query else ""), ""
        )
    matched = match_signatures(body_without_echo, endpoint_signatures)
    if not result.error and matched:
        sample = result.body[:400].replace("\n", "\\n")
        return Finding(
            title=f"Cloud metadata access ({payload.provider})",
            severity="critical",
            verdict=VERDICT_CONFIRMED,
            request_url=result.url,
            param_name="",  # filled by scanner
            param_location="",
            payload_category=payload.category,
            payload_value=payload.value,
            provider=payload.provider,
            evidence=(
                f"response matched metadata signatures: {', '.join(matched)}\n"
                f"body sample: {sample}"
            ),
            baseline_status=baseline.status_code,
            result_status=result.status_code,
            elapsed=result.elapsed,
        )
    return None


def classify_reflection(
    result: HTTPResult,
    payload: ProbePayload,
    baseline: HTTPResult,
) -> Finding | None:
    """Confirmed non-blind SSRF: the injected callback URL content leaks back."""
    if payload.payload_id and payload.payload_id in result.body and not result.error:
        return Finding(
            title="Out-of-band callback reflected in response",
            severity="high",
            verdict=VERDICT_CONFIRMED,
            request_url=result.url,
            param_name="",
            param_location="",
            payload_category=payload.category,
            payload_value=payload.value,
            evidence=(
                f"unique token '{payload.payload_id}' from the callback URL "
                f"appears in the application response; the server fetched and "
                f"rendered attacker-controlled content"
            ),
            baseline_status=baseline.status_code,
            result_status=result.status_code,
            elapsed=result.elapsed,
        )
    return None


def classify_internal_diff(
    result: HTTPResult,
    payload: ProbePayload,
    baseline: HTTPResult,
) -> Finding | None:
    """Diff-based signal that the parameter performed a server-side fetch."""
    if result.error:
        # connection errors to internal hosts are still a useful signal when
        # they differ from the baseline behaviour
        if baseline.error is None:
            return Finding(
                title="Parameter reached a server-side fetch (error behaviour differs)",
                severity="low",
                verdict=VERDICT_INFO,
                request_url=result.url,
                param_name="",
                param_location="",
                payload_category=payload.category,
                payload_value=payload.value,
                evidence=f"baseline returned HTTP {baseline.status_code}; "
                f"payload produced transport error: {result.error}",
                baseline_status=baseline.status_code,
                result_status=0,
                elapsed=result.elapsed,
            )
        return None

    leaked_ips = extract_internal_ips(result.body)
    changed = bodies_differ_enough(baseline, result)
    if changed and (leaked_ips or result.status_code != baseline.status_code):
        evidence_lines = [f"response changed vs baseline (status {baseline.status_code} -> {result.status_code})"]
        if leaked_ips:
            evidence_lines.append(f"internal-looking IPs leaked in response: {', '.join(leaked_ips[:10])}")
        return Finding(
            title="Parameter behaviour changes on internal URL input",
            severity="medium" if leaked_ips else "low",
            verdict=VERDICT_LIKELY if leaked_ips else VERDICT_INFO,
            request_url=result.url,
            param_name="",
            param_location="",
            payload_category=payload.category,
            payload_value=payload.value,
            evidence="\n".join(evidence_lines),
            baseline_status=baseline.status_code,
            result_status=result.status_code,
            elapsed=result.elapsed,
        )
    return None


def classify_timing(
    results: list[tuple[ProbePayload, HTTPResult]],
    baseline: HTTPResult,
) -> list[Finding]:
    """Time-based blind port detection against 127.0.0.1.

    Open ports typically make the server-side fetch wait for protocol
    negotiation, while closed ports fail fast.  The heuristic compares each
    probe's elapsed time against the fastest probe in the same batch and only
    flags clearly slower outliers.
    """
    clean = [(p, r) for p, r in results if r.error or r.elapsed > 0]
    if len(clean) < 4:
        return []

    fastest = min(r.elapsed for _, r in clean)
    findings: list[Finding] = []
    for payload, result in clean:
        if result.elapsed > fastest + 0.75 and result.elapsed > 1.0:
            findings.append(
                Finding(
                    title=f"Possible internal service on port {payload.port} (time-based)",
                    severity="medium",
                    verdict=VERDICT_LIKELY,
                    request_url=result.url,
                    param_name="",
                    param_location="",
                    payload_category=payload.category,
                    payload_value=payload.value,
                    provider=None,
                    evidence=(
                        f"probe elapsed {result.elapsed:.2f}s vs fastest {fastest:.2f}s; "
                        f"error={result.error or 'none'}"
                    ),
                    baseline_status=baseline.status_code,
                    result_status=result.status_code,
                    elapsed=result.elapsed,
                )
            )
    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse equivalent findings.

    Metadata and callback probes are deduplicated per provider/param (every
    host encoding of the same metadata service would otherwise repeat); other
    categories keep one finding per distinct injected value.
    """
    seen: dict[tuple[str, str, str, str], Finding] = {}
    for finding in findings:
        if finding.payload_category in {"metadata", "callback"}:
            key = (
                finding.severity,
                finding.payload_category,
                finding.provider or "",
                finding.param_name,
            )
        else:
            key = (
                finding.severity,
                finding.payload_category,
                finding.payload_value,
                finding.param_name,
            )
        if key not in seen:
            seen[key] = finding
    return sorted(seen.values(), key=lambda f: f.sort_key())
