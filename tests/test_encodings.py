"""Host-encoding bypass variants must resolve to the same IP a naive
validator would block."""

import unittest

from ssrf_scanner.payloads.encodings import (
    host_variants,
    to_decimal,
    to_hex_variants,
    to_octal_variants,
    to_shorthand,
)

METADATA_IP = "169.254.169.254"


class EncodingsTest(unittest.TestCase):
    def test_to_decimal(self):
        self.assertEqual(to_decimal(METADATA_IP), "2852039166")
        self.assertIsNone(to_decimal("metadata.google.internal"))

    def test_to_hex_variants(self):
        variants = to_hex_variants(METADATA_IP)
        self.assertIn("0xA9FEA9FE", variants)
        self.assertIn("0xA9.0xFE.0xA9.0xFE", variants)

    def test_to_octal_variants(self):
        self.assertEqual(to_octal_variants(METADATA_IP), ["0251.0376.0251.0376"])

    def test_to_shorthand(self):
        self.assertEqual(to_shorthand(METADATA_IP), "169.254.43518")

    def test_host_variants_includes_original_and_is_deduped(self):
        variants = host_variants(METADATA_IP)
        self.assertIn(METADATA_IP, variants)
        self.assertEqual(len(variants), len(set(variants)))
        self.assertGreater(len(variants), 1)

    def test_host_variants_non_ip_host_has_no_numeric_forms(self):
        variants = host_variants("metadata.google.internal")
        self.assertEqual(variants, ["metadata.google.internal", "metadata.google.internal."])


if __name__ == "__main__":
    unittest.main()
