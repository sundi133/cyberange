#!/usr/bin/env python3
"""Review and sign imported modules.

The importer (``import_atomics.py``) lands every module as ``signed: false``.
The service refuses to execute an unsigned module - that is the hard safety
gate at the heart of the platform. This script is how a human reviewer flips
the gate on a curated depth batch, so a customer can grow coverage per tactic
without hand-authoring content.

The workflow is deliberately small:

  1. ``--list [--tactic X --platform Y --risk Z]`` shows the staged catalog so
     the reviewer picks what to look at next.
  2. ``--preview MOD-ID [...]`` prints the full review context for one or more
     modules: command, risk flags, elevation, source, suggested class.
  3. ``--sign MOD-ID [...] --reviewer NAME --class S0|S1|S2 [--notes T]``
     flips ``signed`` to true, replaces the import's suggested class with the
     reviewer's real one, and appends an append-only entry to the signing
     log. ``--class S2`` requires ``--acknowledge-s2`` (high-impact; approval
     chain is "Administrator + explicit scenario policy").
  4. ``--batch path/to/batch.json --reviewer NAME`` signs a curated batch in
     one go. The batch file is a list of ``{"id","class","notes"?}`` entries;
     see ``examples/sign-batches/README.md`` for the format.
  5. ``--unsign MOD-ID --reviewer NAME --reason T`` revokes a signing. The
     log keeps both events, so the record of what was ever trusted is
     complete.
  6. ``--audit`` prints the signing log.

Nothing in the control plane trusts a module that is only in the signing log:
the ``signed`` boolean on the module itself is the gate. The log is there so a
later reviewer, auditor, or incident investigator can see who signed what, and
when. It is append-only, gitignored, and local to the operator - this is a
staging-side tool, not a sync protocol.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
STAGED = ROOT / "backend/cyberrange/seed/modules.staged.json"
LOG = ROOT / "backend/cyberrange/seed/_signing_log.jsonl"
VALID_CLASSES = ("S0", "S1", "S2")   # PROHIBITED is never signed.


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _load_staged() -> list[dict]:
    if not STAGED.exists():
        return []
    try:
        return json.loads(STAGED.read_text())
    except json.JSONDecodeError as exc:
        print(f"ERROR: {STAGED} is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _save_staged(mods: list[dict]) -> None:
    STAGED.write_text(json.dumps(mods, indent=2) + "\n")


def _append_log(entry: dict) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def _risk_flags(m: dict) -> list[str]:
    return list((m.get("_import") or {}).get("risk_flags") or [])


def _by_id(mods: list[dict], mod_id: str) -> dict | None:
    return next((m for m in mods if m.get("id") == mod_id), None)


# -- commands -------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> int:
    """Reviewer intake: compact table of staged modules, filterable."""
    mods = _load_staged()
    if args.tactic:
        mods = [m for m in mods
                if args.tactic.upper() in [t.upper() for t in m.get("technique_ids", [])]
                or args.tactic.lower() in (m.get("tactic") or "").lower()]
    if args.platform:
        mods = [m for m in mods if m.get("platform") == args.platform]
    if args.risk:
        mods = [m for m in mods if args.risk in _risk_flags(m)]
    if args.unsigned_only:
        mods = [m for m in mods if not m.get("signed")]
    if args.signed_only:
        mods = [m for m in mods if m.get("signed")]

    if not mods:
        print("(no modules match)")
        return 0

    def _row(m):
        state = "SIGNED" if m.get("signed") else "pending"
        tech = ",".join(m.get("technique_ids") or [])[:14]
        risk = ",".join(_risk_flags(m)) or "-"
        klass = m.get("safety_class") or "-"
        return (m["id"][:36], state, m.get("platform", "")[:7], klass,
                tech, risk[:30], (m.get("name") or "")[:46])

    header = ("MODULE ID", "STATE", "PLAT", "CLS", "TECH", "RISK", "NAME")
    rows = [_row(m) for m in mods]
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*header))
    print(fmt.format(*("-" * w for w in widths)))
    for r in rows:
        print(fmt.format(*r))
    print(f"\n  {len(rows)} module(s)")
    return 0


def cmd_preview(args: argparse.Namespace) -> int:
    """Full review context for one or more modules."""
    mods = _load_staged()
    missing = [i for i in args.ids if _by_id(mods, i) is None]
    if missing:
        print(f"not in staged catalog: {', '.join(missing)}", file=sys.stderr)
        return 2
    for mod_id in args.ids:
        m = _by_id(mods, mod_id)
        imp = m.get("_import") or {}
        print(f"\n{'=' * 76}")
        print(f"  {m['id']}  {'(SIGNED)' if m.get('signed') else '(pending review)'}")
        print(f"{'=' * 76}")
        print(f"  Name:        {m.get('name')}")
        print(f"  Source:      {imp.get('source', '?')}")
        print(f"  Technique:   {','.join(m.get('technique_ids') or [])} "
              f"(ATT&CK {imp.get('attack_technique', '?')})")
        print(f"  Platform:    {m.get('platform')}")
        print(f"  Executor:    {imp.get('executor')} "
              f"(elevation: {imp.get('elevation_required')})")
        print(f"  Suggested:   {imp.get('suggested_class', '?')}  "
              f"(risk flags: {', '.join(imp.get('risk_flags') or ['-'])})")
        print(f"  Current:     safety_class={m.get('safety_class')}  "
              f"signed={m.get('signed')}")
        exe = m.get("execution")
        cmd_display = (
            " ".join(exe["cmd"]) if exe and "cmd" in exe
            else imp.get("candidate_command") or "(no command)"
        )
        print(f"  Command:     {cmd_display[:300]}"
              + (" ..." if cmd_display and len(cmd_display) > 300 else ""))
        print(f"  Cleanup:     {(m.get('cleanup') or '-')[:200]}")
    print()
    return 0


def _sign_one(mods: list[dict], mod_id: str, reviewer: str, klass: str,
              notes: str | None, acknowledge_s2: bool
              ) -> tuple[str, str, dict | None]:
    """Apply one signing on the in-memory module list.

    Returns ``(status, detail, pending_log_entry)``. The caller is responsible
    for writing the staged file AND the log entry together, so a --dry-run or
    a failed save leaves the audit trail honest.
    """
    m = _by_id(mods, mod_id)
    if m is None:
        return "missing", f"{mod_id}: not in staged catalog", None
    if m.get("safety_class") == "PROHIBITED":
        return "refused", f"{mod_id}: PROHIBITED cannot be signed", None
    if not m.get("technique_ids") or not m.get("platform"):
        return "refused", f"{mod_id}: missing technique_ids or platform", None
    if klass not in VALID_CLASSES:
        return "refused", f"{mod_id}: class must be one of {VALID_CLASSES}", None
    if klass == "S2" and not acknowledge_s2:
        return "refused", f"{mod_id}: S2 requires --acknowledge-s2", None
    if m.get("signed"):
        return "noop", f"{mod_id}: already signed (class {m.get('safety_class')})", None

    # Flip the gate. The reviewer's class REPLACES the import's suggestion,
    # since suggested_class was heuristic from risk flags.
    signed_at = _now()
    m["safety_class"] = klass
    m["approval"] = "Security content reviewer"
    m["signed"] = True
    m["_review"] = {
        "reviewer": reviewer,
        "signed_at": signed_at,
        "signed_class": klass,
        "replaces_suggested": (m.get("_import") or {}).get("suggested_class"),
        "notes": notes or "",
    }

    log_entry = {
        "ts": signed_at,
        "action": "sign",
        "module_id": mod_id,
        "reviewer": reviewer,
        "class": klass,
        "notes": notes or "",
        "risk_flags": _risk_flags(m),
    }
    return "signed", f"{mod_id}: signed as {klass}", log_entry


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign one or more modules by ID."""
    reviewer = args.reviewer or getpass.getuser()
    mods = _load_staged()
    statuses = {"signed": [], "noop": [], "refused": [], "missing": []}
    pending_log: list[dict] = []
    for mod_id in args.ids:
        status, detail, log_entry = _sign_one(
            mods, mod_id, reviewer=reviewer, klass=args.cls,
            notes=args.notes, acknowledge_s2=args.acknowledge_s2)
        statuses[status].append(detail)
        if log_entry is not None:
            pending_log.append(log_entry)
        print(f"  [{status}] {detail}")

    if statuses["signed"] and not args.dry_run:
        _save_staged(mods)
        for entry in pending_log:
            _append_log(entry)
    elif args.dry_run and statuses["signed"]:
        print("\n  --dry-run: no changes written")

    print(f"\n  signed:{len(statuses['signed'])}  "
          f"already:{len(statuses['noop'])}  "
          f"refused:{len(statuses['refused'])}  "
          f"missing:{len(statuses['missing'])}")
    return 0 if not (statuses["refused"] or statuses["missing"]) else 1


def cmd_batch(args: argparse.Namespace) -> int:
    """Sign a curated batch from a JSON manifest.

    Format: a list of ``{"id","class","notes"?}`` plus an optional
    top-level ``{"reviewer","notes","modules":[...]}`` wrapper.

    Reviewer precedence: ``--reviewer`` on the CLI always wins. Otherwise the
    manifest's ``reviewer`` is used. Otherwise ``$USER``. The placeholder
    string from the shipped templates is refused so a signing never ends up
    audited under "REPLACE-WITH-YOUR-REVIEWER-IDENTITY".
    """
    path = pathlib.Path(args.batch)
    if not path.exists():
        print(f"batch file not found: {path}", file=sys.stderr)
        return 2
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(f"batch is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if isinstance(doc, dict):
        manifest_reviewer = doc.get("reviewer") or ""
        shared_notes = doc.get("notes") or ""
        entries = doc.get("modules") or []
    else:
        manifest_reviewer = ""
        shared_notes = ""
        entries = doc

    reviewer = args.reviewer or manifest_reviewer or getpass.getuser()
    if "REPLACE-WITH" in reviewer:
        print("refusing to sign under the template placeholder reviewer; "
              "pass --reviewer or edit the manifest.", file=sys.stderr)
        return 2

    mods = _load_staged()
    statuses = {"signed": [], "noop": [], "refused": [], "missing": []}
    pending_log: list[dict] = []
    for entry in entries:
        mod_id = entry["id"]
        klass = entry.get("class") or "S1"
        notes = entry.get("notes") or shared_notes
        status, detail, log_entry = _sign_one(
            mods, mod_id, reviewer=reviewer, klass=klass,
            notes=notes, acknowledge_s2=args.acknowledge_s2)
        statuses[status].append(detail)
        if log_entry is not None:
            pending_log.append(log_entry)
        print(f"  [{status}] {detail}")

    if statuses["signed"] and not args.dry_run:
        _save_staged(mods)
        for entry in pending_log:
            _append_log(entry)
    elif args.dry_run and statuses["signed"]:
        print("\n  --dry-run: no changes written")

    print(f"\n  signed:{len(statuses['signed'])}  "
          f"already:{len(statuses['noop'])}  "
          f"refused:{len(statuses['refused'])}  "
          f"missing:{len(statuses['missing'])}")
    return 0 if not (statuses["refused"] or statuses["missing"]) else 1


def cmd_unsign(args: argparse.Namespace) -> int:
    """Revoke a signing. Keeps the log entry so history is complete."""
    reviewer = args.reviewer or getpass.getuser()
    mods = _load_staged()
    m = _by_id(mods, args.id)
    if m is None:
        print(f"{args.id}: not in staged catalog", file=sys.stderr)
        return 2
    if not m.get("signed"):
        print(f"{args.id}: already unsigned")
        return 0
    m["signed"] = False
    m["approval"] = "PENDING REVIEW - revoked"
    m.pop("_review", None)
    _save_staged(mods)
    _append_log({
        "ts": _now(),
        "action": "unsign",
        "module_id": args.id,
        "reviewer": reviewer,
        "reason": args.reason or "",
    })
    print(f"  [unsigned] {args.id}: revoked")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Print the signing log."""
    if not LOG.exists():
        print("(no signing log yet)")
        return 0
    for line in LOG.read_text().splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            print(f"  ! malformed log line: {line[:80]}", file=sys.stderr)
            continue
        if args.module and entry.get("module_id") != args.module:
            continue
        if args.reviewer and entry.get("reviewer") != args.reviewer:
            continue
        tag = entry.get("action", "?").upper()
        extra = (f"class={entry['class']}" if entry.get("class")
                 else f"reason={entry.get('reason', '')}")
        print(f"  {entry.get('ts', '-')}  [{tag:<6}] "
              f"{entry.get('module_id', '-'):<36}  by {entry.get('reviewer', '-')}  {extra}")
    return 0


# -- CLI ------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="show the staged catalog")
    p.add_argument("--tactic", help="filter by technique id (T####) or tactic text")
    p.add_argument("--platform", choices=("linux", "windows", "macos", "unknown"))
    p.add_argument("--risk", choices=("download", "destructive", "credential",
                                       "persistence", "privilege"))
    p.add_argument("--unsigned-only", action="store_true")
    p.add_argument("--signed-only", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("preview", help="full review context for module(s)")
    p.add_argument("ids", nargs="+")
    p.set_defaults(func=cmd_preview)

    p = sub.add_parser("sign", help="sign one or more modules")
    p.add_argument("ids", nargs="+")
    p.add_argument("--reviewer", help="reviewer identity (default: $USER)")
    p.add_argument("--class", dest="cls", required=True, choices=VALID_CLASSES)
    p.add_argument("--notes")
    p.add_argument("--acknowledge-s2", action="store_true",
                   help="required to sign at S2")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("batch", help="sign a curated batch from a JSON file")
    p.add_argument("batch", help="path to the batch manifest")
    p.add_argument("--reviewer", help="reviewer identity (default: $USER or batch value)")
    p.add_argument("--acknowledge-s2", action="store_true",
                   help="required for any S2 entry in the batch")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser("unsign", help="revoke a signing")
    p.add_argument("id")
    p.add_argument("--reviewer", help="reviewer identity (default: $USER)")
    p.add_argument("--reason", help="why the signing is being revoked")
    p.set_defaults(func=cmd_unsign)

    p = sub.add_parser("audit", help="print the signing log")
    p.add_argument("--module", help="filter to one module id")
    p.add_argument("--reviewer", help="filter to one reviewer")
    p.set_defaults(func=cmd_audit)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
