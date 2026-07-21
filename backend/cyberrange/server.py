"""Stdlib HTTP server exposing the CyberRange REST API (FR-14) + static UI.

Auth is a lightweight header-based identity for the MVP: callers send
`X-CR-Role` and `X-CR-User`. In production this is replaced by SSO/OIDC
(spec section 6); the RBAC layer is unchanged.
"""

from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import catalog, rbac
from .db import Database
from .service import CyberRangeService, ServiceError

FRONTEND_DIR = Path(__file__).parent.parent.parent / "frontend"

_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
}


class Router:
    def __init__(self):
        self.routes: list[tuple[str, re.Pattern, callable]] = []

    def add(self, method: str, pattern: str, handler):
        regex = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")
        self.routes.append((method, regex, handler))

    def match(self, method: str, path: str):
        for m, regex, handler in self.routes:
            if m != method:
                continue
            match = regex.match(path)
            if match:
                return handler, match.groupdict()
        return None, None


def build_router(svc: CyberRangeService) -> Router:
    r = Router()

    # ---- catalog (FR-01) ----
    r.add("GET", "/api/health", lambda ctx: {"status": "ok", "service": "cyberrange"})
    r.add("GET", "/api/tactics", lambda ctx: catalog.tactics())
    r.add("GET", "/api/reference", lambda ctx: catalog.reference())
    r.add("GET", "/api/topologies", lambda ctx: catalog.topologies())
    r.add("GET", "/api/topologies/{tid}",
          lambda ctx: catalog.get_topology(ctx["params"]["tid"])
          or _notfound("topology"))

    def scenarios_handler(ctx):
        q = ctx["query"]
        return catalog.search_scenarios(
            role=_first(q, "role"), tactic=_first(q, "tactic"),
            difficulty=_first(q, "difficulty"), technique=_first(q, "technique"),
            platform=_first(q, "platform"), query=_first(q, "q"),
        )
    r.add("GET", "/api/scenarios", scenarios_handler)
    r.add("GET", "/api/scenarios/{sid}",
          lambda ctx: catalog.get_scenario(ctx["params"]["sid"]) or _notfound("scenario"))

    def modules_handler(ctx):
        q = ctx["query"]
        return catalog.search_modules(
            platform=_first(q, "platform"), safety_class=_first(q, "safety_class"),
            technique=_first(q, "technique"), tactic=_first(q, "tactic"),
        )
    r.add("GET", "/api/modules", modules_handler)
    r.add("GET", "/api/modules/{mid}",
          lambda ctx: catalog.get_module(ctx["params"]["mid"]) or _notfound("module"))
    r.add("GET", "/api/detection-rules", lambda ctx: catalog.detection_rules())

    # ---- ranges (FR-03) ----
    r.add("GET", "/api/ranges", lambda ctx: svc.list_ranges(_first(ctx["query"], "tenant")))
    r.add("GET", "/api/ranges/{rid}", lambda ctx: svc.get_range(ctx["params"]["rid"]))

    def create_range(ctx):
        b = ctx["body"]
        return svc.create_range(ctx["user"], ctx["role"], b["scenario_id"],
                                tenant=b.get("tenant", "default"),
                                ttl_hours=int(b.get("ttl_hours", 8)))
    r.add("POST", "/api/ranges", create_range)

    def range_action(ctx):
        b = ctx["body"]
        return svc.lifecycle_action(ctx["user"], ctx["role"],
                                    ctx["params"]["rid"], b["action"])
    r.add("POST", "/api/ranges/{rid}/actions", range_action)

    # ---- exercises ----
    r.add("GET", "/api/exercises",
          lambda ctx: svc.list_exercises(_first(ctx["query"], "range_id")))
    r.add("GET", "/api/exercises/{exid}", lambda ctx: svc.get_exercise(ctx["params"]["exid"]))

    def start_exercise(ctx):
        return svc.start_exercise(ctx["user"], ctx["role"], ctx["body"]["range_id"])
    r.add("POST", "/api/exercises", start_exercise)

    r.add("GET", "/api/exercises/{exid}/timeline",
          lambda ctx: svc.timeline(ctx["params"]["exid"]))

    def inject(ctx):
        b = ctx["body"]
        return svc.inject(ctx["user"], ctx["role"], ctx["params"]["exid"],
                          b["text"], b.get("type", "instructor"))
    r.add("POST", "/api/exercises/{exid}/injects", inject)

    def execute_module(ctx):
        b = ctx["body"]
        return svc.execute_module(ctx["user"], ctx["role"], ctx["params"]["exid"],
                                  b["module_id"], b.get("inputs"))
    r.add("POST", "/api/exercises/{exid}/modules", execute_module)

    def submit_evidence(ctx):
        b = ctx["body"]
        return svc.submit_evidence(ctx["user"], ctx["role"], ctx["params"]["exid"],
                                   description=b["description"],
                                   classification=b.get("classification", "synthetic"),
                                   linked_event=b.get("linked_event"))
    r.add("POST", "/api/exercises/{exid}/evidence", submit_evidence)
    r.add("GET", "/api/exercises/{exid}/evidence",
          lambda ctx: svc.list_evidence(ctx["params"]["exid"]))

    def record_detection(ctx):
        b = ctx["body"]
        return svc.record_detection(ctx["user"], ctx["role"], ctx["params"]["exid"],
                                    technique_id=b["technique_id"], verdict=b["verdict"],
                                    rule_version=b.get("rule_version", "v1"),
                                    latency_s=float(b.get("latency_s", 0)),
                                    fp_context=b.get("fp_context", ""))
    r.add("POST", "/api/exercises/{exid}/detections", record_detection)
    r.add("GET", "/api/exercises/{exid}/detections",
          lambda ctx: svc.list_detections(ctx["params"]["exid"]))

    def score(ctx):
        b = ctx["body"]
        return svc.score_exercise(ctx["user"], ctx["role"], ctx["params"]["exid"],
                                  b.get("raw_scores", {}), penalties=b.get("penalties"),
                                  overrides=b.get("overrides"))
    r.add("POST", "/api/exercises/{exid}/score", score)
    r.add("GET", "/api/exercises/{exid}/derived-scores",
          lambda ctx: svc.derived_dimension_scores(ctx["params"]["exid"]))

    def end_exercise(ctx):
        return svc.end_exercise(ctx["user"], ctx["role"], ctx["params"]["exid"])
    r.add("POST", "/api/exercises/{exid}/end", end_exercise)

    r.add("GET", "/api/exercises/{exid}/report",
          lambda ctx: svc.build_report(ctx["params"]["exid"]))

    def purple(ctx):
        b = ctx["body"]
        return svc.purple_compare(b["baseline"], b["replay"])
    r.add("POST", "/api/purple/compare", purple)

    # ---- auth & users (FR-12) ----
    def login(ctx):
        b = ctx["body"]
        return svc.login(b.get("username", ""), b.get("password", ""))
    r.add("POST", "/api/login", login)

    def logout(ctx):
        if ctx.get("token"):
            svc.logout(ctx["token"])
        return {"ok": True}
    r.add("POST", "/api/logout", logout)

    def whoami(ctx):
        return {"username": ctx["user"], "role": ctx["role"],
                "display_name": ctx.get("display_name") or ctx["user"],
                "permissions": sorted(rbac.permissions_for(ctx["role"]))}
    r.add("GET", "/api/me", whoami)

    r.add("GET", "/api/roles", lambda ctx: rbac.role_matrix())

    r.add("GET", "/api/users", lambda ctx: svc.list_users(ctx["user"], ctx["role"]))

    def create_user(ctx):
        b = ctx["body"]
        return svc.create_user(ctx["user"], ctx["role"], b.get("username", ""),
                               b.get("password", ""), b.get("role", ""),
                               b.get("display_name"))
    r.add("POST", "/api/users", create_user)

    def set_active(ctx):
        b = ctx["body"]
        return svc.set_user_active(ctx["user"], ctx["role"],
                                   ctx["params"]["username"], bool(b.get("active", True)))
    r.add("POST", "/api/users/{username}/active", set_active)

    # ---- admin ----
    r.add("GET", "/api/audit", lambda ctx: svc.audit_log(int(_first(ctx["query"], "limit") or 200)))

    return r


def _first(query: dict, key: str):
    v = query.get(key)
    return v[0] if v else None


def _notfound(kind: str):
    raise ServiceError(f"Unknown {kind}", 404)


PUBLIC_ROUTES = {("POST", "/api/login"), ("GET", "/api/health")}


class _Handler(BaseHTTPRequestHandler):
    router: Router = None
    svc: CyberRangeService = None
    dev_auth: bool = False
    server_version = "CyberRange/0.1"

    def log_message(self, fmt, *args):  # quieter default logging
        pass

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, path):
        if path in ("/", ""):
            path = "/index.html"
        target = (FRONTEND_DIR / path.lstrip("/")).resolve()
        try:
            target.relative_to(FRONTEND_DIR.resolve())
        except ValueError:
            self._send_json({"error": "forbidden"}, 403)
            return
        if not target.is_file():
            self._send_json({"error": "not found"}, 404)
            return
        ctype = _STATIC_TYPES.get(target.suffix, "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            if method == "GET":
                return self._serve_static(path)
            self._send_json({"error": "not found"}, 404)
            return

        handler, params = self.router.match(method, path)
        if handler is None:
            self._send_json({"error": f"no route for {method} {path}"}, 404)
            return

        # Identity resolution: a Bearer session token is the real path. Header
        # identity (X-CR-Role/X-CR-User) is a dev/testing convenience and is
        # OFF unless dev_auth is enabled (CR_DEV_AUTH=1) — otherwise a public
        # deployment would grant admin to any unauthenticated caller.
        token = None
        display_name = None
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

        is_public = (method, path) in PUBLIC_ROUTES
        role = user = None
        if token:
            session = self.svc.resolve_token(token)
            if not session and not is_public:
                self._send_json({"error": "invalid or expired session"}, 401)
                return
            if session:
                role = session["role"]
                user = session["username"]
                display_name = session["display_name"]
        elif self.dev_auth:
            role = self.headers.get("X-CR-Role", "admin")
            user = self.headers.get("X-CR-User", "anonymous")
            if role not in rbac.ROLES:
                self._send_json({"error": f"unknown role '{role}'"}, 401)
                return

        if role is None and not is_public:
            self._send_json({"error": "authentication required"}, 401)
            return
        if role is None:  # public route reached without identity
            role, user = "admin", "anonymous"

        body = {}
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._send_json({"error": "invalid JSON body"}, 400)
                return

        ctx = {
            "params": params, "query": parse_qs(parsed.query),
            "body": body, "role": role, "user": user,
            "token": token, "display_name": display_name,
        }
        try:
            result = handler(ctx)
            self._send_json(result if result is not None else {})
        except ServiceError as exc:
            self._send_json({"error": str(exc)}, exc.status)
        except rbac.AuthorizationError as exc:
            self._send_json({"error": str(exc)}, 403)
        except KeyError as exc:
            self._send_json({"error": f"missing field: {exc}"}, 400)
        except Exception as exc:  # noqa: BLE001 - surface unexpected errors as 500
            self._send_json({"error": f"internal error: {exc}"}, 500)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def make_server(host: str = "127.0.0.1", port: int = 8080,
                db_path: str | None = None,
                dev_auth: bool = False) -> ThreadingHTTPServer:
    db = Database(db_path)
    svc = CyberRangeService(db)
    router = build_router(svc)
    handler = type("BoundHandler", (_Handler,),
                   {"router": router, "svc": svc, "dev_auth": dev_auth})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.cyberrange_service = svc  # type: ignore[attr-defined]
    return httpd


def run(host: str = "127.0.0.1", port: int = 8080, db_path: str | None = None,
        dev_auth: bool | None = None):
    if dev_auth is None:
        dev_auth = os.environ.get("CR_DEV_AUTH", "").lower() in ("1", "true", "yes")
    httpd = make_server(host, port, db_path, dev_auth=dev_auth)
    mode = "DEV header-auth ENABLED" if dev_auth else "token auth only"
    print(f"CyberRange control plane listening on http://{host}:{port} ({mode})")
    print(f"Dashboard: http://{host}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.shutdown()
