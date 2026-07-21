"""CLI entrypoint: `python -m cyberrange [serve|demo|catalog]`."""

from __future__ import annotations

import argparse
import json
import sys

from . import catalog, __version__
from .db import Database
from .service import CyberRangeService
from .server import run


def _cmd_serve(args):
    run(host=args.host, port=args.port, db_path=args.db)


def _cmd_catalog(args):
    print(json.dumps({
        "scenarios": [s["id"] for s in catalog.scenarios()],
        "modules": [m["id"] for m in catalog.modules()],
        "topologies": [t["id"] for t in catalog.topologies()],
        "tactics": len(catalog.tactics()),
    }, indent=2))


def _cmd_demo(args):
    """Run a full exercise lifecycle end-to-end and print the report."""
    db = Database(":memory:")
    svc = CyberRangeService(db)
    actor, role = "instructor-1", "instructor"

    rng = svc.create_range(actor, role, "CR-PHISH-001")
    print(f"Created range {rng['id']} for {rng['scenario_id']} ({rng['state']})")

    for action in ("preflight", "provision", "seed", "ready"):
        rng = svc.lifecycle_action(actor, role, rng["id"], action)
        print(f"  -> {rng['state']}")

    ex = svc.start_exercise(actor, role, rng["id"])
    print(f"Started exercise {ex['id']}")

    svc.execute_module("red-1", "red", ex["id"], "CR-MOD-PHISH-001")
    svc.execute_module("red-1", "red", ex["id"], "CR-MOD-EXEC-WIN-001")
    svc.inject(actor, role, ex["id"], "Synthetic user reports suspicious attachment")
    svc.record_detection(actor, role, ex["id"], technique_id="T1059",
                         verdict="detected", rule_version="v1", latency_s=42.0)
    svc.submit_evidence("blue-1", "blue", ex["id"],
                        description="PowerShell child of Outlook captured")

    score = svc.score_exercise(actor, role, ex["id"], {
        "red_execution": 80, "detection": 70, "investigation": 65,
        "response": 60, "collaboration": 75,
    })
    print(f"Score: {score['total']} (weighted {score['weighted_before_penalty']})")

    svc.end_exercise(actor, role, ex["id"])
    report = svc.build_report(ex["id"])
    print("\n--- REPORT ---")
    print(json.dumps(report, indent=2, default=str))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cyberrange",
                                     description="CyberRange control plane MVP")
    parser.add_argument("--version", action="version", version=f"cyberrange {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="run the API + dashboard server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--db", default=None, help="SQLite path (default: backend/data/cyberrange.db)")
    p_serve.set_defaults(func=_cmd_serve)

    p_cat = sub.add_parser("catalog", help="print catalog summary")
    p_cat.set_defaults(func=_cmd_catalog)

    p_demo = sub.add_parser("demo", help="run an end-to-end exercise in memory")
    p_demo.set_defaults(func=_cmd_demo)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
