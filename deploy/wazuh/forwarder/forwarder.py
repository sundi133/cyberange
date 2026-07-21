"""Wazuh -> CyberRange alert forwarder.

Tails the Wazuh manager's alerts.json (shared volume), keeps only alerts that
originated from CyberRange events (rule group `cyberrange`, carrying an
`exercise_id`), and posts each to CyberRange's /api/siem/alert so it becomes a
real `basis=siem` detection on the exercise timeline.

Standard library only — the forwarder image needs no pip installs.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error

CR_URL = os.environ.get("CYBERRANGE_URL", "http://cyberrange:8080").rstrip("/")
CR_USER = os.environ.get("CR_ADMIN_USER", "admin")
CR_PASS = os.environ.get("CR_ADMIN_PASSWORD", "admin")
ALERTS_PATH = os.environ.get("WAZUH_ALERTS_PATH", "/var/ossec/logs/alerts/alerts.json")
POLL_SECONDS = float(os.environ.get("FORWARDER_POLL_SECONDS", "2"))


def parse_alert(alert: dict) -> dict | None:
    """Map a Wazuh alert JSON to a CyberRange /api/siem/alert body, or None if
    it isn't a CyberRange-originated alert."""
    rule = alert.get("rule", {})
    groups = rule.get("groups", []) or []
    data = alert.get("data", {}) or {}
    exercise_id = data.get("exercise_id")
    if "cyberrange" not in groups or not exercise_id:
        return None
    return {
        "exercise_id": exercise_id,
        "rule_id": str(rule.get("id", "")),
        "level": int(rule.get("level", 0) or 0),
        "description": rule.get("description", ""),
        "technique_id": data.get("technique_id"),
        "full_log": alert.get("full_log", "") or data.get("payload.line", ""),
    }


def _post(path: str, body: dict, token: str | None) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(CR_URL + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def login() -> str:
    for _ in range(30):  # wait for CyberRange to come up
        try:
            status, data = _post("/api/login", {"username": CR_USER, "password": CR_PASS}, None)
            if status == 200 and data.get("token"):
                print(f"[forwarder] authenticated to CyberRange as {CR_USER}", flush=True)
                return data["token"]
            print(f"[forwarder] login failed ({status}): {data}", flush=True)
        except urllib.error.URLError as exc:
            print(f"[forwarder] waiting for CyberRange: {exc}", flush=True)
        time.sleep(3)
    raise SystemExit("[forwarder] could not authenticate to CyberRange")


def follow(path: str):
    """Yield new JSON alert lines as they are appended (handles rotation)."""
    while not os.path.exists(path):
        print(f"[forwarder] waiting for {path}…", flush=True)
        time.sleep(POLL_SECONDS)
    fh = open(path, "r", encoding="utf-8", errors="replace")
    fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    while True:
        line = fh.readline()
        if line:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
            continue
        time.sleep(POLL_SECONDS)
        # detect rotation
        try:
            if os.stat(path).st_ino != inode:
                fh.close()
                fh = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
        except FileNotFoundError:
            pass


def main():
    token = login()
    print(f"[forwarder] tailing {ALERTS_PATH}", flush=True)
    for alert in follow(ALERTS_PATH):
        body = parse_alert(alert)
        if not body:
            continue
        status, resp = _post("/api/siem/alert", body, token)
        if status == 401:  # token expired — re-auth and retry once
            token = login()
            status, resp = _post("/api/siem/alert", body, token)
        if status == 200:
            print(f"[forwarder] → detection: rule {body['rule_id']} "
                  f"{body.get('technique_id')} on {body['exercise_id']}", flush=True)
        else:
            print(f"[forwarder] post failed ({status}): {resp}", flush=True)


if __name__ == "__main__":
    main()
