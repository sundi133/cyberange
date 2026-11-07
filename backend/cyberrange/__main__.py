"""CLI entrypoint: `python -m cyberrange [serve|demo|catalog]`."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import catalog, __version__
from .db import Database
from .service import CyberRangeService
from .server import run


def _cmd_serve(args):
    run(host=args.host, port=args.port, db_path=args.db)


def _cmd_import_atomics(args):
    """Import an Atomic Red Team checkout into the staged (unsigned) catalog."""
    import pathlib
    from . import ingest
    try:
        mods = ingest.import_atomic_dir(args.src, limit=args.limit)
    except ModuleNotFoundError:
        print("PyYAML is required: python3 -m venv .venv && . .venv/bin/activate "
              "&& pip install pyyaml", file=sys.stderr)
        return
    staged = pathlib.Path(args.out) if args.out else (
        pathlib.Path(__file__).parent / "seed" / "modules.staged.json")
    existing = []
    if staged.exists():
        existing = json.loads(staged.read_text() or "[]")
    have = {m["id"] for m in existing}
    added = [m for m in mods if m["id"] not in have]
    staged.write_text(json.dumps(existing + added, indent=2))
    print(f"Imported {len(added)} new modules (of {len(mods)} converted) "
          f"into {staged}")
    print(json.dumps(ingest.import_summary(existing + added), indent=2))
    print("All imported modules are UNSIGNED and cannot run until reviewed and "
          "signed (scripts/sign_modules.py). Signed Linux-shell modules then "
          "become hands-on labs automatically (make seed-labs).")


def _cmd_gen_scenarios(args):
    """Regenerate the committed ART drill scenarios (scenarios.imported.json)."""
    import json as _json
    from . import catalog, scenario_gen
    scs = scenario_gen.generate_scenarios()
    out = catalog.SEED_DIR / "scenarios.imported.json"
    out.write_text(_json.dumps(scs, indent=2) + "\n")
    print(f"Wrote {len(scs)} drill scenarios to {out}")
    print(_json.dumps(scenario_gen.summary(), indent=2))


def _cmd_seed_labs(args):
    """Populate the standing Practice Arena competition with generated labs."""
    from .db import connect
    from . import labs
    svc = CyberRangeService(connect(args.db))
    res = svc.competitions.seed_practice_arena()
    state = "created" if res["created"] else "already populated"
    print(f"Practice Arena {res['id']}: {res['challenges']} labs ({state}).")
    print(json.dumps(labs.lab_summary(), indent=2))


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
    # PORT/HOST env vars let platforms like Railway/Heroku inject the bind port.
    p_serve.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    p_serve.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    p_serve.add_argument("--db", default=None, help="SQLite path (default: backend/data/cyberrange.db)")
    p_serve.set_defaults(func=_cmd_serve)

    p_cat = sub.add_parser("catalog", help="print catalog summary")
    p_cat.set_defaults(func=_cmd_catalog)

    p_labs = sub.add_parser("seed-labs",
                            help="populate the Practice Arena with generated labs")
    p_labs.add_argument("--db", default=None, help="SQLite path (default: backend/data/cyberrange.db)")
    p_labs.set_defaults(func=_cmd_seed_labs)

    p_gen = sub.add_parser("gen-scenarios",
                           help="regenerate committed ART drill scenarios")
    p_gen.set_defaults(func=_cmd_gen_scenarios)

    p_imp = sub.add_parser("import-atomics",
                           help="import an Atomic Red Team checkout (unsigned, for review)")
    p_imp.add_argument("--src", required=True, help="path to atomic-red-team/atomics")
    p_imp.add_argument("--limit", type=int, default=1000)
    p_imp.add_argument("--out", default=None, help="staging file (default: seed/modules.staged.json)")
    p_imp.set_defaults(func=_cmd_import_atomics)

    p_demo = sub.add_parser("demo", help="run an end-to-end exercise in memory")
    p_demo.set_defaults(func=_cmd_demo)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
