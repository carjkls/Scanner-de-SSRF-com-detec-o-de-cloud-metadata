"""Scan orchestrator: discovery -> payload matrix -> async probing -> findings."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from . import discovery as param_discovery
from .callback_server import CallbackServer
from .detector import (
    Finding,
    classify_internal_diff,
    classify_metadata,
    classify_reflection,
    classify_timing,
    dedupe,
)
from .http_client import AsyncHTTPClient, HTTPResult
from ..payloads.generator import (
    ProbePayload,
    callback_payloads,
    internal_payloads,
    metadata_payloads,
    port_timing_payloads,
)


@dataclass
class ScanConfig:
    target_url: str
    method: str = "GET"
    body: str | None = None            # raw request body for POST/PUT
    content_type: str | None = None
    explicit_param: str | None = None
    callback_host: str | None = None   # external OOB endpoint (e.g. webhooK)
    callback_port: int = 9000
    use_local_listener: bool = False
    proxy: str | None = None
    timeout: float = 10.0
    concurrency: int = 10
    max_payloads: int = 60             # per parameter
    max_params: int = 12
    max_total_requests: int = 400
    include_internal: bool = False
    port_probe: bool = False
    insecure_tls: bool = False
    grace_period: float = 4.0          # wait for OOB callbacks after probing
    verbose: bool = False


class SSRFScanner:
    """Coordinates discovery, probing and detection for one target URL."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._log_buffer: list[str] = []

    # ------------------------------------------------------------------ util
    def _log(self, message: str) -> None:
        if self.config.verbose:
            self._log_buffer.append(message)
            print(f"[*] {message}")

    # ------------------------------------------------------------------ main
    async def run(self) -> list[Finding]:
        cfg = self.config
        findings: list[Finding] = []
        listener: CallbackServer | None = None

        async with AsyncHTTPClient(
            timeout=cfg.timeout,
            concurrency=cfg.concurrency,
            proxy=cfg.proxy,
            verify_tls=not cfg.insecure_tls,
        ) as client:
            # 1. baseline ----------------------------------------------------
            self._log(f"fetching baseline: {cfg.target_url}")
            baseline_get = await client.get(cfg.target_url)
            baseline = baseline_get
            if cfg.method.upper() == "POST" and cfg.body:
                baseline = await self._send_with_param(client, None, None)

            # 2. discovery ---------------------------------------------------
            candidates = param_discovery.discover_candidates(
                cfg.target_url,
                html_body=baseline_get.body if not baseline_get.error else None,
                json_body=cfg.body if self._body_is_json() else None,
            )
            if cfg.explicit_param:
                candidates = [c for c in candidates if c.name == cfg.explicit_param] or [
                    param_discovery.CandidateParam(
                        location="query",
                        name=cfg.explicit_param,
                        original_value="",
                        method=cfg.method.upper(),
                        priority=0,
                    )
                ]
            candidates = candidates[: cfg.max_params]
            if not candidates:
                self._log("no injectable parameters discovered")
                return findings
            self._log(
                "candidate parameters: "
                + ", ".join(f"{c.location}:{c.name}" for c in candidates)
            )

            # 3. payload matrix ----------------------------------------------
            payloads: list[ProbePayload] = []
            callback_base: str | None = None
            payloads.extend(metadata_payloads())
            if cfg.callback_host:
                callback_base = cfg.callback_host
            elif cfg.use_local_listener:
                listener = CallbackServer(port=cfg.callback_port)
                await listener.start()
                self._log(f"callback listener on {listener.base_url}")
                callback_base = listener.base_url
            if callback_base:  # type: ignore[possibly-undefined]
                payloads.extend(callback_payloads(callback_base))
            if cfg.include_internal:
                payloads.extend(internal_payloads())
            if cfg.port_probe:
                payloads.extend(port_timing_payloads())
            payloads = payloads[: cfg.max_payloads]
            self._log(f"payload matrix: {len(payloads)} probes x {len(candidates)} params")

            # 4. probing ------------------------------------------------------
            pending_callback_tokens: dict[str, ProbePayload] = {}
            total_budget = cfg.max_total_requests
            for candidate in candidates:
                if total_budget <= 0:
                    self._log("request budget exhausted; stopping")
                    break
                batch = payloads[:total_budget]
                total_budget -= len(batch)
                param_findings, tokens = await self._probe_param(
                    client, candidate, batch, baseline, listener
                )
                pending_callback_tokens.update(tokens)
                findings.extend(param_findings)

            # 5. OOB callback collection ---------------------------------------
            if listener is not None and pending_callback_tokens:
                self._log(
                    f"waiting {cfg.grace_period}s for OOB callbacks "
                    f"({len(pending_callback_tokens)} tokens pending)"
                )
                for token, payload in pending_callback_tokens.items():
                    hit = await listener.wait_for_hit(token, cfg.grace_period)
                    if hit:
                        findings.append(
                            Finding(
                                title="Out-of-band callback received (blind SSRF)",
                                severity="high",
                                verdict="confirmed",
                                request_url=cfg.target_url,
                                param_name="",
                                param_location="",
                                payload_category=payload.category,
                                payload_value=payload.value,
                                evidence=(
                                    f"listener on {listener.base_url} received "
                                    f"{hit.method} {hit.path} from {hit.src_addr}"
                                ),
                            )
                        )
            if listener is not None:
                await listener.stop()

        return dedupe(findings)

    # ------------------------------------------------------------------ internals
    def _body_is_json(self) -> bool:
        body = self.config.body
        if not body:
            return False
        content_type = self.config.content_type
        if content_type and "json" in content_type.lower():
            return True
        try:
            json.loads(body)
            return True
        except (json.JSONDecodeError, TypeError):
            return False

    async def _send_with_param(
        self,
        client: AsyncHTTPClient,
        candidate: param_discovery.CandidateParam | None,
        value: str | None,
    ) -> HTTPResult:
        """Send the configured request, optionally with one param replaced."""
        cfg = self.config
        method = cfg.method.upper()

        if method == "GET" or candidate is None or candidate.location == "query":
            url = cfg.target_url
            if candidate is not None:
                url = param_discovery.inject_query_param(url, candidate.name, value or "")
            return await client.get(url)

        if candidate.location == "json" and cfg.body:
            injected = param_discovery.inject_json_path(cfg.body, candidate.name, value or "")
            return await client.post(
                cfg.target_url,
                data=injected,
                headers={"Content-Type": cfg.content_type or "application/json"},
            )

        # form POST
        try:
            data = dict(pair.split("=", 1) for pair in (cfg.body or "").split("&") if pair)
        except ValueError:
            data = {}
        data[candidate.name] = value or ""
        return await client.post(
            cfg.target_url,
            data=data,
            headers={"Content-Type": cfg.content_type or "application/x-www-form-urlencoded"},
        )

    async def _probe_param(
        self,
        client: AsyncHTTPClient,
        candidate: param_discovery.CandidateParam,
        payloads: list[ProbePayload],
        baseline: HTTPResult,
        listener: CallbackServer | None,
    ) -> tuple[list[Finding], dict[str, ProbePayload]]:
        findings: list[Finding] = []
        callback_tokens: dict[str, ProbePayload] = {}

        tasks = [self._send_with_param(client, candidate, p.value) for p in payloads]
        results = await asyncio.gather(*tasks)

        port_results: list[tuple[ProbePayload, HTTPResult]] = []
        for payload, result in zip(payloads, results):
            self._log(
                f"probe {candidate.location}:{candidate.name} -> {payload.category}"
                f"{'/' + (payload.provider or '') if payload.provider else ''}"
                f" [status={result.status_code} err={result.error is not None} t={result.elapsed:.2f}s]"
            )

            if payload.category == "metadata":
                finding = classify_metadata(result, payload, payload.signatures, baseline)
                if finding:
                    findings.append(finding)
                continue

            if payload.category == "callback":
                finding = classify_reflection(result, payload, baseline)
                if finding:
                    findings.append(finding)
                if listener is not None:
                    callback_tokens[payload.payload_id] = payload
                else:
                    findings.append(
                        Finding(
                            title="OOB callback URL injected (manual verification needed)",
                            severity="info",
                            verdict="info",
                            request_url=result.url,
                            param_name=candidate.name,
                            param_location=candidate.location,
                            payload_category=payload.category,
                            payload_value=payload.value,
                            evidence=(
                                f"token '{payload.payload_id}' was embedded in an OOB URL; "
                                "check your external callback console for this token"
                            ),
                        )
                    )
                continue

            if payload.category == "port":
                port_results.append((payload, result))
                continue

            finding = classify_internal_diff(result, payload, baseline)
            if finding:
                finding.param_name = candidate.name
                finding.param_location = candidate.location
                findings.append(finding)

        if port_results:
            for finding in classify_timing(port_results, baseline):
                finding.param_name = candidate.name
                finding.param_location = candidate.location
                findings.append(finding)

        # attach param identity to metadata/callback findings as well
        for finding in findings:
            if not finding.param_name:
                finding.param_name = candidate.name
                finding.param_location = candidate.location

        return findings, callback_tokens
