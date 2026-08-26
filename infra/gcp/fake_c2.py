"""No-upstream mitmproxy addon with fixed, provably inert responses."""

from __future__ import annotations

import json

from mitmproxy import http

TEMPLATES = {
    "/fixture": {"status": "ok", "fixture": True},
    "/register": {"status": "registered", "next": "/fixture"},
    "/config": {"enabled": False, "commands": []},
}


def request(flow: http.HTTPFlow) -> None:
    """Sink every request locally and never contact its requested upstream."""
    body = TEMPLATES.get(flow.request.path, {"status": "sinkholed", "commands": []})
    flow.response = http.Response.make(
        200,
        json.dumps(body).encode(),
        {"Content-Type": "application/json", "X-DRISHTI-No-Upstream": "true"},
    )
