"""Detector classification: true positives, and the echoed-URL false
positive this module used to produce."""

import unittest

from ssrf_scanner.core.detector import Finding, classify_metadata, dedupe, extract_internal_ips
from ssrf_scanner.core.http_client import HTTPResult
from ssrf_scanner.payloads.generator import ProbePayload

BASELINE = HTTPResult(url="http://target/fetch", status_code=200, body="ok")


def _payload(value: str, signatures: tuple[str, ...], provider: str = "AWS") -> ProbePayload:
    return ProbePayload(
        payload_id="tok",
        value=value,
        category="metadata",
        description="",
        provider=provider,
        signatures=signatures,
    )


class ClassifyMetadataTest(unittest.TestCase):
    def test_real_metadata_response_is_confirmed(self):
        payload = _payload(
            "http://169.254.169.254/latest/meta-data/",
            signatures=("ami-id", "instance-id"),
        )
        result = HTTPResult(
            url="http://target/fetch?url=...", status_code=200,
            body="ami-id\ninstance-id\nlocal-ipv4\n",
        )
        finding = classify_metadata(result, payload, payload.signatures, BASELINE)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.verdict, "confirmed")
        self.assertEqual(finding.severity, "critical")

    def test_app_echoing_the_probe_path_in_an_error_is_not_a_false_positive(self):
        # Regression: requests' "Max retries exceeded with url: <path>" (or any
        # app that echoes the failed URL back) must not be mistaken for a real
        # metadata response just because the probe path itself contains the
        # signature text (e.g. Azure WireServer's "?comp=goalstate").
        payload = _payload(
            "http://168.63.129.16/machine/?comp=goalstate",
            signatures=("goalState", "containerId", "instanceId"),
            provider="Azure WireServer",
        )
        result = HTTPResult(
            url="http://target/fetch?url=...", status_code=502,
            body=(
                "fetch error: HTTPConnectionPool(host='168.63.129.16', port=80): "
                "Max retries exceeded with url: /machine/?comp=goalstate"
            ),
        )
        finding = classify_metadata(result, payload, payload.signatures, BASELINE)
        self.assertIsNone(finding)

    def test_transport_error_is_never_confirmed_even_with_signature_text(self):
        payload = _payload(
            "http://169.254.169.254/latest/meta-data/",
            signatures=("ami-id",),
        )
        result = HTTPResult(
            url="http://target/fetch", error="ConnectError: refused", body="ami-id leaked",
        )
        finding = classify_metadata(result, payload, payload.signatures, BASELINE)
        self.assertIsNone(finding)


class ExtractInternalIpsTest(unittest.TestCase):
    def test_finds_rfc1918_ranges(self):
        body = "connecting to 10.0.0.5 and 192.168.1.1, public is 8.8.8.8"
        self.assertEqual(extract_internal_ips(body), ["10.0.0.5", "192.168.1.1"])


class DedupeTest(unittest.TestCase):
    def test_collapses_equivalent_metadata_findings(self):
        make = lambda value: Finding(
            title="Cloud metadata access (AWS)", severity="critical", verdict="confirmed",
            request_url="http://target/fetch?url=" + value, param_name="url",
            param_location="query", payload_category="metadata", payload_value=value,
            provider="AWS",
        )
        findings = [make("http://169.254.169.254/a"), make("http://2852039166/b")]
        self.assertEqual(len(dedupe(findings)), 1)


if __name__ == "__main__":
    unittest.main()
