"""Command-line interface for ssrf-scanner."""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import __version__
from .core.scanner import ScanConfig, SSRFScanner
from .reporting.report import print_findings, save_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssrfscan",
        description=(
            "SSRF scanner with cloud metadata fingerprinting, bypass encodings "
            "and out-of-band callback detection. Only scan systems you are "
            "authorized to test."
        ),
    )
    parser.add_argument("-u", "--url", required=True, help="target URL (include query params)")
    parser.add_argument(
        "--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)"
    )
    parser.add_argument(
        "--data", dest="body", default=None,
        help="request body for POST (form-encoded string or raw JSON)",
    )
    parser.add_argument(
        "--content-type", default=None,
        help="Content-Type for the body (default: auto-detect)",
    )
    parser.add_argument(
        "-p", "--param", dest="param", default=None,
        help="test only this parameter (name or JSON path like $.download_url)",
    )
    parser.add_argument(
        "--callback-host", default=None,
        help="external OOB host, e.g. a webhooK/collaborator root URL "
        "(the scanner embeds unique tokens under it)",
    )
    parser.add_argument(
        "--listen", metavar="HOST:PORT", default=None,
        help="run a built-in callback listener (blind SSRF detection)",
    )
    parser.add_argument("--proxy", default=None, help="HTTP(S) proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (s)")
    parser.add_argument("--concurrency", type=int, default=10, help="parallel requests")
    parser.add_argument("--max-payloads", type=int, default=60, help="payloads per parameter")
    parser.add_argument("--max-params", type=int, default=12, help="max parameters to test")
    parser.add_argument(
        "--include-internal", action="store_true",
        help="also probe generic internal hosts (127.0.0.1, localhost, ::1) and file:// schemes",
    )
    parser.add_argument(
        "--ports", action="store_true",
        help="time-based blind probing of common local ports",
    )
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("-o", "--output", default=None, help="write JSON report to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    use_listener = False
    callback_port = 9000
    if args.listen:
        try:
            host, _, port = args.listen.rpartition(":")
            callback_port = int(port)
        except ValueError:
            print("error: --listen expects HOST:PORT", file=sys.stderr)
            return 2
        use_listener = True

    config = ScanConfig(
        target_url=args.url,
        method=args.method,
        body=args.body,
        content_type=args.content_type,
        explicit_param=args.param,
        callback_host=args.callback_host,
        callback_port=callback_port,
        use_local_listener=use_listener,
        proxy=args.proxy,
        timeout=args.timeout,
        concurrency=args.concurrency,
        max_payloads=args.max_payloads,
        max_params=args.max_params,
        include_internal=args.include_internal,
        port_probe=args.ports,
        insecure_tls=args.insecure,
        verbose=args.verbose,
    )

    scanner = SSRFScanner(config)
    try:
        findings = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130

    print_findings(findings, args.url)
    if args.output:
        save_json(findings, args.output)
        print(f"[+] JSON report saved to {args.output}")
    return 0 if findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
