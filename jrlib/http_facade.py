"""Stable ``/api/jobs`` routes on the JacHammer server.

Jaclang 0.16 records ``@restspec`` metadata and then ignores it. The live
server only dispatches ``POST /function/<name>`` and ``POST /walker/<name>``.
The functions in ``server.jac`` stay registered there. This module adds the
job routes the product UI and external clients call, by wrapping the handler
factory before ``jac start`` binds the socket.

``resolve`` is the routing table. The wrapper only reads the request and
writes JSON.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from jrlib.api import (
    create_job,
    delete_job,
    get_events,
    get_findings,
    get_job,
    get_log,
    get_report,
    list_jobs,
    reproduce,
)

_MAX_BODY = 65536
_LOG = logging.getLogger("jacrift.http")
_INSTALLED = False

_GET_ACTIONS = {
    "log": get_log,
    "events": get_events,
    "findings": get_findings,
    "report": get_report,
}


def _status_for(payload: dict) -> int:
    if payload.get("ok"):
        return 200
    error = str(payload.get("error", ""))
    if error in {"job_not_found", "finding_not_found"}:
        return 404
    return 400


def _match(path: str) -> tuple[str, str | None, str | None] | None:
    parsed = urlparse(path)
    raw = parsed.path or ""
    if raw != "/api/jobs" and not raw.startswith("/api/jobs/"):
        return None
    rest = raw[len("/api/jobs") :].strip("/")
    if rest == "":
        return ("collection", None, None)
    parts = rest.split("/")
    if len(parts) == 1:
        return ("item", parts[0], None)
    if len(parts) == 2:
        return ("item", parts[0], parts[1])
    return ("bad", None, None)


def resolve(method: str, path: str, body: dict | None = None) -> tuple[int, dict] | None:
    """Return ``(status, payload)`` for a job route, or ``None`` if this path is not ours."""
    matched = _match(path)
    if matched is None:
        return None
    kind, job_id, action = matched
    payload_in = body if isinstance(body, dict) else {}
    if kind == "bad":
        return 404, {"ok": False, "error": "not_found"}
    if kind == "collection":
        if method == "GET":
            return 200, list_jobs()
        if method == "POST":
            created = create_job(
                payload_in.get("repository_url", ""),
                payload_in.get("authorization_confirmed"),
                payload_in.get("scope", ""),
                True,
            )
            return _status_for(created), created
        return 405, {"ok": False, "error": "method_not_allowed"}
    if not isinstance(job_id, str):
        return 400, {"ok": False, "error": "invalid_job_id", "job_id": ""}
    if action is None:
        if method == "GET":
            found = get_job(job_id)
            return _status_for(found), found
        if method == "DELETE":
            removed = delete_job(job_id)
            return _status_for(removed), removed
        return 405, {"ok": False, "error": "method_not_allowed"}
    if action == "reproduce":
        if method != "POST":
            return 405, {"ok": False, "error": "method_not_allowed"}
        finding_id = payload_in.get("finding_id", "")
        if not isinstance(finding_id, str):
            finding_id = ""
        replayed = reproduce(job_id, finding_id)
        return _status_for(replayed), replayed
    reader = _GET_ACTIONS.get(action)
    if reader is None:
        return 404, {"ok": False, "error": "not_found"}
    if method != "GET":
        return 405, {"ok": False, "error": "method_not_allowed"}
    read = reader(job_id)
    return _status_for(read), read


def _read_body(handler: object) -> dict:
    headers = getattr(handler, "headers", {})
    try:
        length = int(headers.get("Content-Length", "0") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("malformed_body") from exc
    if length < 0 or length > _MAX_BODY:
        raise ValueError("body_too_large")
    raw = b""
    if length:
        raw = handler.rfile.read(length)
    if not raw:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("body_not_object")
    return data


def _write(handler: object, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _serve(handler: object, method: str) -> bool:
    path = getattr(handler, "path", "")
    if not isinstance(path, str) or _match(path) is None:
        return False
    try:
        body = _read_body(handler) if method == "POST" else {}
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        _write(handler, 400, {"ok": False, "error": "malformed_body"})
        return True
    try:
        resolved = resolve(method, path, body)
    except Exception:
        _LOG.exception("job route failed")
        _write(handler, 500, {"ok": False, "error": "internal_error"})
        return True
    if resolved is None:
        return False
    status, payload = resolved
    _write(handler, status, payload)
    return True


def install_job_routes() -> bool:
    """Wrap ``JacAPIServer.create_handler`` so ``/api/jobs`` is served.

    Safe to call more than once. Must run while the user module loads, before
    ``jac start`` builds the request handler.
    """
    global _INSTALLED
    if _INSTALLED:
        return True
    from jaclang.runtimelib.server import JacAPIServer

    original = JacAPIServer.create_handler
    if getattr(original, "_jacrift_wrapped", False):
        _INSTALLED = True
        return True

    def create_handler(self):
        Handler = original(self)
        base_get = Handler.do_GET
        base_post = Handler.do_POST

        def do_GET(handler, _base=base_get):
            if _serve(handler, "GET"):
                return None
            return _base(handler)

        def do_POST(handler, _base=base_post):
            if _serve(handler, "POST"):
                return None
            return _base(handler)

        def do_DELETE(handler):
            if _serve(handler, "DELETE"):
                return None
            _write(handler, 404, {"ok": False, "error": "not_found"})
            return None

        Handler.do_GET = do_GET
        Handler.do_POST = do_POST
        Handler.do_DELETE = do_DELETE
        return Handler

    create_handler._jacrift_wrapped = True  # type: ignore[attr-defined]
    JacAPIServer.create_handler = create_handler
    _INSTALLED = True
    return True
