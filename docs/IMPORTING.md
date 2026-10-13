# Importing external ATT&CK content

The catalog ships 29 curated, signed modules. To reach CALDERA-scale volume you
**import** a library rather than author it by hand. `scripts/import_atomics.py`
converts Atomic Red Team atomics and CALDERA abilities into CyberRange modules.

## Capacity

The catalog is an in-memory list backed by SQLite. 1000 modules load in ~13 ms
and search in well under a millisecond, so capacity is not the constraint —
measured, not estimated. Past a few hundred modules the catalog grid benefits
from the platform/safety/execution filters (and, eventually, pagination); the
backend is unaffected.

## The safety model — read this first

Importing is **not** trusting. Every imported module is written
**`signed: false`**, and the service refuses to execute any unsigned module —
even for an admin. So nothing an import produces can run until a human:

1. reads the command (the importer flags the risky ones),
2. assigns a real safety class, and
3. signs it.

This is deliberate. Atomic Red Team and CALDERA tests run *real* techniques —
many download tools or change real state — so bulk-loading and running them
would defeat the platform's whole safety posture. The `signed` flag is the gate
that keeps CyberRange from becoming a way to run real malware on a network.

Imported modules land in a **staging file** (`modules.staged.json`), kept
separate from the curated seed (`modules.json`). The catalog lists staged
modules marked **⚠ Unsigned** with their source and review flags; the attack
console shows them disabled. They are visible, not runnable.

## Usage

The importer needs PyYAML. On modern macOS and Debian, `pip install` into the
system Python is blocked (PEP 668), so use a one-time virtual environment — it
keeps PyYAML out of system Python and leaves everything else running on it:

```bash
python3 -m venv .venv
source .venv/bin/activate      # re-run this in each new terminal
pip install pyyaml
```

It is an offline ops tool — the control plane itself stays standard-library
only and only reads the JSON it produces.

```bash
# Atomic Red Team — https://github.com/redcanaryco/atomic-red-team (MIT)
git clone https://github.com/redcanaryco/atomic-red-team
python3 scripts/import_atomics.py --format atomic --src atomic-red-team/atomics

# CALDERA abilities — https://github.com/mitre/caldera (Apache-2.0)
git clone https://github.com/mitre/caldera
python3 scripts/import_atomics.py --format caldera --src caldera/data/abilities

# cap the count, or write elsewhere
python3 scripts/import_atomics.py --format atomic --src atomic-red-team/atomics \
    --limit 500 --out backend/cyberrange/seed/modules.staged.json
```

It prints a review report — counts by platform, how many are real-capable now
(Linux shell) versus simulate-only (Windows/macOS until the VM tier), and how
many carry risk flags (download, destructive, credential, persistence,
privilege). Review the flagged ones first.

## What converts, and how

| Source field | CyberRange module |
|---|---|
| `attack_technique` / `technique_id` | `technique_ids` (collapsed to the parent, e.g. T1059.004 → T1059) |
| test / ability `name` | `name` |
| `executor.command` | `execution.cmd` for Linux shell; otherwise recorded in `_import.candidate_command` |
| `cleanup_command` / `cleanup` | `cleanup` |
| `input_arguments` | `inputs` |
| `supported_platforms` / executor platform | `platform` |
| `elevation_required` / privilege | proposed `safety_class` (S2 if elevated or risk-flagged, else S1) |

Only **Linux shell** executors (`sh`, `bash`) get a real execution spec and run
in a container. Windows PowerShell and `command_prompt` tests are recorded but
left to simulate until the [VM tier](../deploy/vm/PROXMOX_SETUP.md), so they do
not look falsely runnable.

Provenance and review metadata live under each module's `_import` key: source,
original technique (with sub-technique), executor, elevation, and the risk
flags.

## Promoting a module to runnable

After review, move the module from `modules.staged.json` into `modules.json`,
set a real `safety_class`, confirm the `execution` spec is what you intend, and
set `signed: true`. On the next server start it is a first-class catalog module.
Until then it stays listed-but-blocked.
