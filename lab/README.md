# ssrf-scanner lab

A small, intentionally vulnerable Flask app for exercising the scanner
against a real (but harmless, localhost-only) target.

## Run it

```bash
pip install -e .[lab]
python lab/app.py
# listening on http://127.0.0.1:5001
```

Routes:

- `GET /` — a page with an HTML form (`url` field) for discovery testing.
- `GET /fetch?url=...` — fetches the given URL server-side and returns the body.
- `POST /preview` with `{"download_url": "..."}` — same, via JSON body.

## Try the scanner against it

```bash
# query-param, diff/reflection based
ssrfscan -u "http://127.0.0.1:5001/fetch?url=https://example.com" --include-internal

# JSON body
ssrfscan -u "http://127.0.0.1:5001/preview" --method POST \
  --data '{"download_url": "https://example.com"}' -p '$.download_url'

# blind SSRF via the built-in OOB listener
ssrfscan -u "http://127.0.0.1:5001/fetch?url=x" --listen 127.0.0.1:9000
```

Expect `--include-internal` to surface the `127.0.0.1`/`localhost` probes as
findings (the lab happily fetches them), and the OOB listener to record a
hit since `/fetch` makes a real outbound request with the injected URL.

Real cloud-metadata findings (AWS/GCP/Azure/etc.) will only fire when
`ssrfscan` itself runs on an actual cloud instance that `/fetch` can reach —
this lab has no way to fake those IPs locally.
