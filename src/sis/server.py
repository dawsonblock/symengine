"""Zero-dependency localhost JSON HTTP API. For remote exposure add TLS reverse proxy."""
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import MappingProxyType
from urllib.parse import parse_qs, urlsplit
from . import __version__
from .errors import SISError, InvalidInput
from .service import Service
from .validation import canonical

MAX_BODY = 524288

# Explicit POST route inventory. New routes must be classified before they can
# be dispatched. Unclassified paths are denied; the role field in JSON is
# never consulted. ``operator`` retains the documented unkeyed loopback demo
# behavior, while keyed/deployed mode requires the separate SIS_ADMIN_KEY.
POST_ROUTE_HANDLERS = {
    "/v1/induce": "study",
    "/v1/predict": "predict",
    "/v1/predict-batch": "predict_batch",
    "/v1/transfer": "transfer",
    "/v1/transfer-batch": "transfer_batch",
    "/v1/feedback": "feedback",
    "/v1/chat": "chat",
    "/v1/query": "query",
    "/v1/benchmark": "benchmark",
    "/v1/retire": "retire",
    "/v1/skills/study": "skill_study",
    "/v1/skills/experience": "experience_study",
    "/v1/skills/predict": "skill_predict",
    "/v1/skills/feedback": "skill_feedback",
    "/v1/skills/retire": "skill_retire",
    "/v1/skills/benchmark": "skill_benchmark",
    "/v1/workflows/capture": "workflow_capture",
    "/v1/workflows/study": "workflow_study",
    "/v1/workflows/predict": "workflow_predict",
    "/v1/workflows/retire": "workflow_retire",
    "/v1/code/capture": "code_capture",
    "/v1/code/study": "code_study",
    "/v1/code/preview": "code_preview",
    "/v1/code/retire": "code_retire",
}
OPERATOR_POST_ROUTES = frozenset({
    "/v1/induce", "/v1/feedback", "/v1/chat", "/v1/retire",
    "/v1/skills/study", "/v1/skills/experience", "/v1/skills/feedback", "/v1/skills/retire",
    "/v1/workflows/study", "/v1/workflows/retire", "/v1/code/study", "/v1/code/retire",
})
READ_ONLY_POST_ROUTES = frozenset({
    "/v1/predict", "/v1/predict-batch", "/v1/transfer", "/v1/transfer-batch",
    "/v1/query", "/v1/benchmark", "/v1/skills/predict", "/v1/skills/benchmark",
    "/v1/workflows/capture", "/v1/workflows/predict", "/v1/code/capture", "/v1/code/preview",
})
POST_ROUTE_ACCESS = MappingProxyType({
    **{path: "operator" for path in OPERATOR_POST_ROUTES},
    **{path: "reader" for path in READ_ONLY_POST_ROUTES},
})


def _handler_class(*, key, admin_key, service, v3_only, v3_service):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"SIS/{__version__}"

        def log_message(self, fmt, *args):
            # Avoid logging request bodies, examples, prediction inputs, or authentication tokens.
            return

        def respond(self, code, value):
            body = canonical(value).encode("utf8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def authorized(self):
            if not key:
                return True  # Only loopback may bind without a key.
            return hmac.compare_digest(self.headers.get("X-SIS-Key", "").encode("utf8"),
                                       key.encode("utf8"))

        def mutation_authorized(self):
            # With an API key enabled, absence of an independent admin key
            # disables mutations instead of silently elevating the read key.
            if admin_key:
                return hmac.compare_digest(self.headers.get("X-SIS-Admin-Key", "").encode("utf8"),
                                           admin_key.encode("utf8"))
            return not bool(key)  # trusted local demo remains backward compatible

        def do_GET(self):
            try:
                if not self.authorized():
                    return self.respond(401, {"error": "unauthorized"})
                u = urlsplit(self.path)
                if v3_only and u.path.startswith("/v1/"):
                    return self.respond(404, {"error": "not found"})
                if u.path == "/health":
                    payload = {
                        "status": "ok",
                        "service": "symbolic-induction",
                        "version": __version__,
                    }
                    if v3_service is not None:
                        v3_health = v3_service.health()
                        payload["v3"] = v3_health
                        if not v3_health.get("ok"):
                            payload["status"] = "degraded"
                            return self.respond(503, payload)
                    return self.respond(200, payload)
                if u.path == "/v1/tools":
                    return self.respond(200, {'tools':service.tools()})
                if u.path == "/v1/rules":
                    qs = parse_qs(u.query)
                    return self.respond(200, {"rules": service.list_rules(qs.get("namespace", ["default"])[0],
                                              qs.get("include_suspended", ["false"])[0] == "true")})
                if u.path == "/v1/skills":
                    qs = parse_qs(u.query)
                    return self.respond(200, {"skills":service.skill_list(qs.get('namespace',['default'])[0],
                                      qs.get('include_inactive',['false'])[0]=='true')})
                if u.path == "/v1/skills/audit":
                    return self.respond(200, service.skill_audit())
                if u.path == "/v1/workflows":
                    qs=parse_qs(u.query)
                    return self.respond(200, {'workflows':service.workflow_list(qs.get('namespace',['default'])[0])})
                if u.path == "/v1/workflows/audit":
                    return self.respond(200, service.workflow_audit())
                if u.path == "/v1/code":
                    qs=parse_qs(u.query)
                    return self.respond(200, {'recipes':service.code_list(qs.get('namespace',['default'])[0])})
                if u.path == "/v1/code/audit":
                    return self.respond(200, service.code_audit())
                if u.path == "/v1/audit":
                    return self.respond(200, service.registry.verify_audit())
                return self.respond(404, {"error": "not found"})
            except SISError as exc:
                self.respond(400, {"error": str(exc)})

        def do_POST(self):
            try:
                path = urlsplit(self.path).path
                if path.startswith("/v3/"):
                    if v3_service is None:
                        return self.respond(404, {"error": "not found"})
                    length = self.headers.get("Content-Length")
                    if length is None or not length.isdecimal() or int(length) > MAX_BODY:
                        return self.respond(413, {"error": "Content-Length required; max 512 KiB"})
                    raw = self.rfile.read(int(length))
                    try:
                        data = json.loads(raw)
                    except (ValueError, UnicodeDecodeError):
                        return self.respond(400, {"error": "invalid JSON"})
                    try:
                        code, body = v3_service.handle(path, data, self.headers)
                    except Exception:  # noqa: BLE001 - fail closed, no detail
                        # The v3 boundary must fail closed with a response,
                        # not a dropped connection. Never echo request data.
                        return self.respond(500, {"error": "internal_error"})
                    return self.respond(code, body)
                if not self.authorized():
                    return self.respond(401, {"error": "unauthorized"})
                if v3_only and path.startswith("/v1/"):
                    return self.respond(404, {"error": "not found"})
                length = self.headers.get("Content-Length")
                if length is None or not length.isdecimal() or int(length) > MAX_BODY:
                    return self.respond(413, {"error": "Content-Length required; max 512 KiB"})
                raw = self.rfile.read(int(length))
                try:
                    data = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    return self.respond(400, {"error": "invalid JSON"})
                if path not in POST_ROUTE_HANDLERS:
                    return self.respond(404, {"error": "not found"})
                access = POST_ROUTE_ACCESS.get(path)
                if access not in {"reader", "operator"}:
                    return self.respond(403, {"error": "route policy missing"})
                if access == "operator" and not self.mutation_authorized():
                    return self.respond(403, {"error": "operator authorization required"})
                return self.respond(200, getattr(service, POST_ROUTE_HANDLERS[path])(data))
            except (SISError, KeyError, TypeError, ValueError) as exc:
                self.respond(400, {"error": str(exc)[:300]})


    return Handler


def create_server(host="127.0.0.1", port=8765, *, db_path="sis.sqlite3",
                  v3_service=None):
    key = os.getenv("SIS_API_KEY", "")
    admin_key = os.getenv("SIS_ADMIN_KEY", "")
    if host not in ("127.0.0.1", "::1", "localhost") and not key:
        raise InvalidInput("non-loopback server requires SIS_API_KEY; use TLS reverse proxy for public exposure")
    if key and len(key.encode("utf8")) < 24:
        raise InvalidInput("SIS_API_KEY must be at least 24 UTF-8 bytes")
    if admin_key and len(admin_key.encode("utf8")) < 24:
        raise InvalidInput("SIS_ADMIN_KEY must be at least 24 UTF-8 bytes")
    if key and admin_key and hmac.compare_digest(key, admin_key):
        raise InvalidInput("SIS_ADMIN_KEY must differ from SIS_API_KEY")
    # A v3-only deployment exposes the authenticated guidance boundary and
    # nothing else. Legacy /v1 learning routes are not production guidance
    # and must not be reachable when this flag is set, so the legacy store
    # is not even opened.
    # Enabling the v3 boundary isolates the legacy learning routes by
    # default; a migration window can opt back in explicitly.
    v3_only = os.getenv("SIS_V3_ONLY") == "1" or (
        v3_service is not None
        and os.getenv("SIS_ALLOW_LEGACY_V1") != "1")
    if v3_only and v3_service is None:
        raise InvalidInput("SIS_V3_ONLY requires a configured v3 serving service")
    service = None if v3_only else Service(
        db_path, enable_llm=os.getenv("SIS_ENABLE_LLM") == "1")
    httpd = ThreadingHTTPServer((host, port), _handler_class(
        key=key, admin_key=admin_key, service=service, v3_only=v3_only,
        v3_service=v3_service))
    httpd.sis_service = service
    httpd.sis_keyed = bool(key)
    httpd.sis_admin_keyed = bool(admin_key)
    return httpd


def serve(host="127.0.0.1", port=8765, *, db_path="sis.sqlite3",
          v3_service=None):
    httpd = create_server(host, port, db_path=db_path,
                          v3_service=v3_service)
    key = httpd.sis_keyed
    admin_key = httpd.sis_admin_keyed
    print(f"SIS listening at http://{host}:{port} (local-only by default); key {'enabled' if key else 'not configured'}, operator mutations {'enabled' if admin_key or not key else 'disabled'}", flush=True)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
        if httpd.sis_service is not None:
            httpd.sis_service.registry.close()
