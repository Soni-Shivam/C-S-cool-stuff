"""No-upstream mitmproxy addon with allowlisted deterministic response templates."""
from mitmproxy import http


TEMPLATES = {
    "/fixture": {"status": "ok", "fixture": True},
    "/register": {"status": "registered", "next": "/fixture"},
    "/config": {"enabled": False, "commands": []},
}


def request(flow: http.HTTPFlow) -> None:
    body = TEMPLATES.get(flow.request.path, {"status": "sinkholed", "commands": []})
    flow.response = http.Response.make(
        200, __import__("json").dumps(body).encode(), {"Content-Type": "application/json", "X-DRISHTI-No-Upstream": "true"}
    )
