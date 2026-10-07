#!/usr/bin/env python3
"""Seed a running CyberRange with the accounts a red/blue lab needs.

Creating an instructor, a red operator and a blue analyst by hand before every
test is the slowest part of trying the product. This does it in one call, and
optionally stands up a range and starts the exercise so there is something to
join.

    make serve                     # in one terminal
    python3 scripts/seed_demo.py   # in another

Idempotent: accounts that already exist are left alone.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

USERS = [
    ("prof",  "profpass", "instructor", "Instructor"),
    ("red1",  "redpass",  "red",        "Red Operator"),
    ("blue1", "bluepass", "blue",       "Blue Analyst"),
]


def call(base: str, method: str, path: str, body=None, token=None):
    url = base + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    # localhost must not go through any configured proxy
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=20) as resp:
            return json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:200]
        raise SystemExit(f"{method} {path} -> {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"Cannot reach {base}. Is the server running (`make serve`)?\n  {exc}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("CR_URL", "http://127.0.0.1:8080"))
    ap.add_argument("--admin-user", default=os.environ.get("CR_ADMIN_USER", "admin"))
    ap.add_argument("--admin-pass", default=os.environ.get("CR_ADMIN_PASSWORD", "admin"))
    ap.add_argument("--scenario", default="CR-DOCKER-001",
                    help="scenario to stage a range for (default: %(default)s)")
    ap.add_argument("--no-range", action="store_true",
                    help="only create the accounts")
    args = ap.parse_args()

    base = args.url.rstrip("/") + "/api"

    health = call(base, "GET", "/health")
    mode = health["execution"]["mode"]
    tier = health.get("targets", {}).get("tier", "?")

    session = call(base, "POST", "/login",
                   {"username": args.admin_user, "password": args.admin_pass})
    token = session["token"]

    existing = {u["username"] for u in (call(base, "GET", "/users", token=token) or [])}
    for username, password, role, display in USERS:
        if username in existing:
            continue
        call(base, "POST", "/users", token=token, body={
            "username": username, "password": password,
            "role": role, "display_name": display})

    staged = None
    if not args.no_range:
        rng = call(base, "POST", "/ranges", token=token, body={"scenario_id": args.scenario})
        for action in ("preflight", "provision", "seed", "ready"):
            call(base, "POST", f"/ranges/{rng['id']}/actions", token=token,
                 body={"action": action})
        staged = call(base, "POST", "/exercises", token=token, body={"range_id": rng["id"]})

    print(f"\n  CyberRange at {args.url}")
    print(f"  Execution: {mode}" + ("" if mode == "docker" else
          "   <- no Docker daemon reachable; modules will be simulated"))
    print(f"  Targets:   {tier} tier\n")
    print("  Username  Password   Role         Opens on")
    print("  " + "-" * 50)
    print(f"  {args.admin_user:<9} {args.admin_pass:<10} admin        Catalog")
    for username, password, role, _ in USERS:
        lands = "Catalog" if role == "instructor" else "Exercise"
        print(f"  {username:<9} {password:<10} {role:<12} {lands}")

    if staged:
        print(f"\n  Exercise {staged['id']} is running on scenario {args.scenario}.")
        print("  red1 can attack it now; blue1 sees the SOC console.")
    print("\n  Sign red and blue in from two different browsers (or one private")
    print("  window) so both sides are live at once.\n")

    if mode != "docker":
        print("  Note: without Docker, blue sees almost nothing to hunt. Simulated")
        print("  runs emit only telemetry that is redacted from the defender, so")
        print("  start Docker Desktop and restart the server for a real exercise.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
