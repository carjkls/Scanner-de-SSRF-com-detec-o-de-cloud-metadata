"""Intentionally vulnerable Flask app for exercising ssrf-scanner locally.

Every route below does a real server-side fetch of attacker-controlled input
with no validation — do not deploy this anywhere reachable from outside your
own machine.

    pip install -e .[lab]
    python lab/app.py
"""

from __future__ import annotations

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/")
def index() -> str:
    # an HTML <form> so discovery.py's form-harvesting path has something to find
    return """
    <html><body>
      <h1>ssrf-scanner lab</h1>
      <form method="get" action="/fetch">
        <input name="url" value="https://example.com">
        <button type="submit">Fetch</button>
      </form>
    </body></html>
    """


@app.get("/fetch")
def fetch() -> tuple[str, int]:
    """Classic SSRF: fetches whatever URL is given in the query string."""
    url = request.args.get("url", "")
    if not url:
        return "missing url param", 400
    try:
        resp = requests.get(url, timeout=3)
        return resp.text[:4000], resp.status_code
    except requests.RequestException as exc:
        return f"fetch error: {exc}", 502


@app.post("/preview")
def preview():
    """JSON-body SSRF: fetches whatever is at $.download_url."""
    body = request.get_json(silent=True) or {}
    url = body.get("download_url", "")
    if not url:
        return jsonify(error="missing download_url"), 400
    try:
        resp = requests.get(url, timeout=3)
        return jsonify(status=resp.status_code, body=resp.text[:4000])
    except requests.RequestException as exc:
        return jsonify(error=str(exc)), 502


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
