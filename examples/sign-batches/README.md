# Reviewer sign batches

A **sign batch** is a short JSON manifest that lists imported module IDs plus
the real safety class the reviewer is assigning to each. Running

```
python3 scripts/sign_modules.py batch examples/sign-batches/<file>.json \
    --reviewer "<your-name>" [--acknowledge-s2]
```

flips the `signed` gate on each entry, replaces the import's heuristic
`suggested_class` with the reviewer's real class, writes a `_review` block,
and appends to the local signing log (`backend/cyberrange/seed/_signing_log.jsonl`).

The batch format exists so a review is one explicit list, not a sequence of
one-off CLI calls, and so what was ever trusted — and by whom — is a
reviewable artifact in its own right.

## Format

```json
{
  "reviewer": "security.lead@example.com",
  "notes": "Q4 depth sprint — Linux execution + evasion variants",
  "modules": [
    {"id": "CR-ATOMIC-T1059_001-00", "class": "S1"},
    {"id": "CR-ATOMIC-T1070_004-01", "class": "S1", "notes": "benign tmpfs cleanup"},
    {"id": "CR-ATOMIC-T1548_003-00", "class": "S2", "notes": "sudo misconfig; policy approved"}
  ]
}
```

A bare list (no wrapper) also works:

```json
[
  {"id": "CR-ATOMIC-T1059_001-00", "class": "S1"},
  {"id": "CR-ATOMIC-T1059_006-02", "class": "S1"}
]
```

## Workflow

1. **Import** content from Atomic Red Team / CALDERA (see `docs/IMPORTING.md`).
   Everything lands `signed: false` in `modules.staged.json`.
2. **Intake**: `scripts/sign_modules.py list --unsigned-only --platform linux`
   gives a filterable table so you choose what to review first.
3. **Preview** each candidate: `scripts/sign_modules.py preview <ID> [<ID>...]`
   prints the command, risk flags, source, and suggested class — the reviewer
   context in one place.
4. **Compose** a batch file (one of the templates in this directory, or your
   own).
5. **Sign** the batch. S2 entries also need `--acknowledge-s2`.
6. **Audit** anytime: `scripts/sign_modules.py audit [--reviewer X]
   [--module <ID>]`.

Revoke a signing with `scripts/sign_modules.py unsign <ID> --reason "…"`;
the log keeps both events.

## Templates in this directory

Each template lists real ATT&CK IDs on the import side (so the review has a
concrete scope), with the module IDs *as the atomic importer writes them*
(`CR-ATOMIC-<TECHNIQUE>-<INDEX>`). The IDs in a template are placeholders
pointing at the techniques to review — the reviewer runs the importer, maps
the actual IDs the importer produced, and edits the batch file to match
before running the sign.

- `depth-linux-execution.json` — Execution and Defense Evasion depth on the
  Linux-real path (where no VM tier is required).
- `depth-credential-access.json` — Credential-access breadth (brute force,
  password spraying, MFA fatigue surfaces).
- `depth-persistence-lateral.json` — Persistence and lateral-movement
  variants: WMI, LOLBins, additional service persistence.
