"""Parameter discovery for SSRF candidate injection points.

Three sources are harvested:

* query-string parameters of the target URL (GET)
* HTML ``<form>`` fields on the target page (GET/POST form)
* string values inside a user-supplied JSON body (POST/PUT), tracked by JSON
  path so injection can restore the original document structure
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit

from bs4 import BeautifulSoup

# Parameter names that historically correlate with server-side URL fetching.
URL_PARAM_HINTS = {
    "url", "uri", "path", "src", "source", "link", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return", "return_url",
    "returnurl", "rurl", "next", "continue", "target", "host", "domain",
    "site", "document", "doc", "page", "file", "load", "fetch", "feed",
    "img", "image", "proxy", "gateway", "content", "view", "window",
    "callback", "cb", "share", "reference", "ref", "open", "resource",
}


@dataclass
class CandidateParam:
    """A single injectable parameter location."""

    location: str  # "query" | "form" | "json"
    name: str      # parameter name, or JSON path like "$.download_url"
    original_value: str
    method: str    # "GET" | "POST"
    priority: int  # 0 = highest (name looks URL-ish)

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.method} {self.location}:{self.name}"


def _priority_for(name: str) -> int:
    base = name.rsplit(".", 1)[-1].strip("[]").lower()
    if base in URL_PARAM_HINTS:
        return 0
    if any(hint in base for hint in ("url", "uri", "link", "src", "dest", "target", "fetch")):
        return 1
    return 2


def from_query_string(url: str) -> list[CandidateParam]:
    split = urlsplit(url)
    params = parse_qsl(split.query, keep_blank_values=True)
    return [
        CandidateParam(
            location="query",
            name=name,
            original_value=value,
            method="GET",
            priority=_priority_for(name),
        )
        for name, value in params
    ]


def from_html(html: str) -> list[CandidateParam]:
    """Extract candidate parameters from every form on the page.

    Forms without an explicit action are mapped onto the current page, which
    matches how most applications behave.
    """
    found: dict[tuple[str, str, str], CandidateParam] = {}
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "GET").strip().upper()
        if method not in {"GET", "POST"}:
            method = "GET"
        location = "query" if method == "GET" else "form"
        # mark the form key with the action so different forms don't collide
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name or (inp.get("type") or "").lower() in {"submit", "button", "hidden"}:
                continue
            value = inp.get("value") or ""
            key = (location, action, name)
            if key not in found or found[key].priority > _priority_for(name):
                found[key] = CandidateParam(
                    location=location,
                    name=name,
                    original_value=value,
                    method=method,
                    priority=_priority_for(name),
                )
    # collapse forms sharing a location/name: keep the first occurrence
    seen: dict[tuple[str, str], CandidateParam] = {}
    for cand in found.values():
        seen.setdefault((cand.location, cand.name), cand)
    return list(seen.values())


def from_json_body(body: str) -> list[CandidateParam]:
    """Enumerate string values in a JSON document, tracked by JSON path."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []

    candidates: list[CandidateParam] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}" if path else f"$.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        elif isinstance(node, str):
            candidates.append(
                CandidateParam(
                    location="json",
                    name=path or "$",
                    original_value=node,
                    method="POST",
                    priority=_priority_for(path.rsplit(".", 1)[-1]),
                )
            )

    walk(doc, "")
    return candidates


def discover_candidates(
    target_url: str,
    html_body: str | None = None,
    json_body: str | None = None,
) -> list[CandidateParam]:
    """Merge every discovery source and rank candidates."""
    candidates: list[CandidateParam] = []
    candidates.extend(from_query_string(target_url))
    if html_body:
        candidates.extend(from_html(html_body))
    if json_body:
        candidates.extend(from_json_body(json_body))

    # deduplicate by (location, name)
    unique: dict[tuple[str, str], CandidateParam] = {}
    for cand in candidates:
        unique.setdefault((cand.location, cand.name), cand)

    ranked = sorted(unique.values(), key=lambda c: (c.priority, c.location, c.name))
    return ranked


# ---------------------------------------------------------------------------
# injection helpers
# ---------------------------------------------------------------------------

def inject_query_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with ``name`` replaced by ``value`` (added if absent)."""
    split = urlsplit(url)
    pairs = parse_qsl(split.query, keep_blank_values=True)
    if not any(existing == name for existing, _ in pairs):
        pairs.append((name, ""))
    pairs = [(key, value if key == name else original) for key, original in pairs]
    return split._replace(query=urlencode(pairs)).geturl()


def inject_form_value(data: dict[str, str], name: str, value: str) -> dict[str, str]:
    updated = dict(data)
    updated[name] = value
    return updated


def inject_json_path(body: str, path: str, value: str) -> str:
    """Set the value at ``path`` (e.g. ``$.download_url`` or ``$.a[0].b``)."""
    doc = json.loads(body)

    tokens: list[tuple[str, str]] = []  # (kind, key) kind in {"key", "index"}
    stripped = path.lstrip("$").strip(".")
    buffer = ""
    for char in stripped + ".":
        if char == ".":
            if buffer:
                tokens.append(("key", buffer))
                buffer = ""
        elif char == "[":
            if buffer:
                tokens.append(("key", buffer))
                buffer = ""
        elif char == "]":
            tokens.append(("index", buffer))
            buffer = ""
        else:
            buffer += char

    def set_value(node: object, tokens: list[tuple[str, str]]) -> None:
        if not tokens:
            return
        kind, key = tokens[0]
        if kind == "key":
            if not isinstance(node, dict):
                raise ValueError(f"cannot apply key {key!r} to {type(node).__name__}")
            if len(tokens) == 1:
                node[key] = value
            else:
                set_value(node[key], tokens[1:])
        else:
            if not isinstance(node, list):
                raise ValueError(f"cannot apply index {key!r} to {type(node).__name__}")
            index = int(key)
            if len(tokens) == 1:
                node[index] = value
            else:
                set_value(node[index], tokens[1:])

    if not tokens:
        # "$" alone: the whole document is the value (weird but possible)
        return json.dumps(value)
    set_value(doc, tokens)
    return json.dumps(doc)
