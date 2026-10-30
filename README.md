# ssrf-scanner

Modular SSRF scanner: parameter discovery, cloud metadata fingerprinting,
host-encoding bypasses and out-of-band (blind) callback detection.

> **Only scan systems you are authorized to test.** This tool sends
> server-side-fetch probes (including requests to cloud instance-metadata
> endpoints) and can trigger real outbound traffic from the target.

## Install

```bash
pip install -e .
```

Python 3.10+. Core dependencies: `httpx`, `beautifulsoup4`.

## Usage

```bash
# scan a query parameter, reflected/diff-based detection only
ssrfscan -u "https://target.example/fetch?url=https://example.com"

# run the built-in OOB listener for blind SSRF confirmation
ssrfscan -u "https://target.example/fetch?url=x" --listen 0.0.0.0:9000

# point at an external collaborator-style callback host instead
ssrfscan -u "https://target.example/fetch?url=x" --callback-host http://abc123.oast.fun

# POST with a JSON body, testing one specific field
ssrfscan -u "https://target.example/api/preview" --method POST \
  --data '{"download_url": "https://example.com"}' -p '$.download_url'

# also probe generic internal hosts/schemes and time-based port scanning
ssrfscan -u "https://target.example/fetch?url=x" --include-internal --ports

# save a JSON report
ssrfscan -u "https://target.example/fetch?url=x" -o report.json
```

Run `ssrfscan --help` for the full flag list (proxy, concurrency, timeouts,
request budget, TLS verification).

## How it works

1. **Discovery** (`core/discovery.py`) — harvests candidate injection points
   from the target's query string, any HTML forms on the page, and string
   values inside a supplied JSON body; ranks them by how URL-ish the
   parameter name looks.
2. **Payload matrix** (`payloads/`) — cloud metadata URLs for 9 providers
   (AWS, GCP, Azure IMDS/WireServer, DigitalOcean, Alibaba, Oracle, ECS,
   Kubernetes) in several host encodings (`payloads/encodings.py`:
   decimal, hex, octal, shorthand, IPv6-mapped), plus OOB callback URLs and
   optional internal-host/scheme/port probes.
3. **Probing** (`core/scanner.py`) — injects each payload into each
   candidate asynchronously, respecting a concurrency limit and total
   request budget.
4. **Detection** (`core/detector.py`) — classifies responses: confirmed
   metadata-signature matches, reflected OOB tokens, response-diff/leaked
   RFC1918-IP heuristics, and time-based port-open heuristics. Findings are
   deduped and sorted by severity.
5. **Reporting** (`reporting/report.py`) — colored console output and
   optional JSON export.

## Testing against a local target

See [`lab/`](lab/) for a small intentionally-vulnerable Flask app you can
run on localhost to try the scanner end to end without touching anything
real.

## Known limitations

- IMDSv2 (AWS) and production Azure/GCP metadata services require headers
  (`X-aws-ec2-metadata-token`, `Metadata: true`, `Metadata-Flavor: Google`)
  that cannot be set through a URL parameter alone. These providers are
  still probed because misconfigured/legacy/proxied deployments can still
  respond; a signature match remains a strong signal either way.
- Time-based port detection is a coarse heuristic (elapsed-time outliers)
  and can produce false positives on a loaded or high-latency target.
