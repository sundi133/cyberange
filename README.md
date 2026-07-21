# CyberRange

**VM-based Red, Blue & Purple team training and validation platform.**

A control-plane MVP implementing the [CyberRange product spec](docs/PRODUCT_SPEC_SUMMARY.md):
isolated range provisioning through a lifecycle state machine, a scenario/TTP
catalog mapped to MITRE ATT&CK, role-aware workspaces, a synchronized evidence
timeline, explainable scoring, Purple-team replay comparison, and an
append-only audit ledger.

This MVP is written against the **Python standard library only** — no pip
install, no build step. It runs anywhere Python 3.10+ is available.

```
┌──────────────┐   REST/JSON    ┌──────────────────────────────────────┐
│  Web         │ ─────────────► │  Control plane (stdlib HTTP + SQLite) │
│  dashboard   │                │  ┌────────┬──────────┬──────────────┐ │
│  (frontend/) │ ◄───────────── │  │catalog │ lifecycle│ scoring/RBAC │ │
└──────────────┘                │  └────────┴──────────┴──────────────┘ │
                                │   service ─► SQLite (ranges, events,   │
                                │              evidence, audit)          │
                                └──────────────────────────────────────┘
```

## Quick start

```bash
# From the repo root
make serve            # http://127.0.0.1:8080  (dashboard + API)
# or:
cd backend && python3 -m cyberrange serve --port 8080
```

Open <http://127.0.0.1:8080/> for the operator dashboard. On first run the
platform seeds a single admin account — **`admin` / `admin`** (override with
`CR_ADMIN_PASSWORD`). Sign in, then use the **Admin** tab to provision users
and assign each a role. See [docs/ROLES.md](docs/ROLES.md) for what every role
can do and the full provisioning flow.

Other entrypoints:

```bash
make demo             # run a full exercise lifecycle end-to-end in memory
make test             # run the 38-test suite (stdlib unittest)
make catalog          # print the seeded content summary
```

## What's implemented (MVP slice of the spec)

| Spec area | Here |
|---|---|
| FR-01 Scenario catalog | `catalog.py` + `seed/` — search/filter scenarios & modules |
| FR-02 Topology templates | `seed/topologies.json` — declarative VM/network/identity templates |
| FR-03 Lifecycle | `lifecycle.py` — full state machine incl. QUARANTINED (admin-only release) |
| FR-06 TTP emulation | 24 signed S0/S1/S2 modules across Windows/Linux/Docker; **real container execution** for modules with an execution spec (see below), simulated otherwise |
| FR-07 Telemetry/timeline | `service.py` — synchronized UTC event timeline with integrity hashes |
| FR-08 Detection content | `detection.py` + `seed/detections.json` — versioned Sigma-like rules that **fire automatically** against real telemetry (MTTD, severity, evidence) |
| FR-09 Scoring | `scoring.py` — weighted, explainable, penalty- and override-aware |
| FR-10 Replay | `purple_compare` — baseline-to-replay coverage delta (not win/lose) |
| FR-11 Reporting | `build_report` — coverage, gaps, evidence, recommendations |
| FR-12 Administration | `rbac.py` + `auth.py` — role→permission model, **user provisioning + login (hashed passwords, session tokens)**, admin panel, audit ledger |
| FR-14 APIs | `server.py` — REST endpoints for lifecycle, catalog, evidence, scoring |
| §8 Safety | unsigned/prohibited modules blocked; S2 gated to instructor/admin |

Seeded content: **7 launch scenarios**, **24 signed behavior modules**,
**15 ATT&CK techniques**, **2 topology templates** — matching the MVP scope in
the spec (§10).

## Roles

Send `X-CR-Role` and `X-CR-User` headers (the dashboard sets these from the
top-right selector). Roles: `admin`, `instructor`, `red`, `blue`, `purple`,
`solo`, `security_leader`. In production these headers are replaced by SSO/OIDC
(spec §6); the RBAC layer is unchanged.

## API tour

```bash
BASE=http://127.0.0.1:8080/api
H='-H X-CR-Role:instructor -H X-CR-User:inst-1 -H Content-Type:application/json'

curl $H $BASE/scenarios                                   # FR-01 catalog
RID=$(curl -s $H -d '{"scenario_id":"CR-PHISH-001"}' $BASE/ranges | jq -r .id)
for a in preflight provision seed ready; do
  curl -s $H -d "{\"action\":\"$a\"}" $BASE/ranges/$RID/actions >/dev/null
done
EX=$(curl -s $H -d "{\"range_id\":\"$RID\"}" $BASE/exercises | jq -r .id)
curl -s $H -d '{"module_id":"CR-MOD-PHISH-001"}' $BASE/exercises/$EX/modules
curl -s $H $BASE/exercises/$EX/timeline                   # FR-07 timeline
curl -s $H -d '{"raw_scores":{"detection":80}}' $BASE/exercises/$EX/score
curl -s $H $BASE/exercises/$EX/report                     # FR-11 report
```

Full endpoint list: [docs/API.md](docs/API.md).

## Running with Docker

```bash
docker compose up            # serves on http://127.0.0.1:8080
```

## Layout

```
backend/
  cyberrange/
    lifecycle.py    range lifecycle state machine (FR-03)
    rbac.py         roles & permissions (FR-12, §8)
    scoring.py      explainable weighted scoring (FR-09)
    catalog.py      content catalog + search (FR-01)
    db.py           SQLite persistence
    service.py      orchestration: ranges, exercises, evidence, audit
    server.py       stdlib HTTP router + static file serving (FR-14)
    __main__.py     CLI: serve | demo | catalog
    seed/           scenarios, modules, topologies, tactics, reference
  tests/            38 unittest tests
frontend/           single-page operator dashboard (no build step)
docs/               spec summary, API reference
```

## Real vs. simulated execution

Behavior modules run through an **execution adapter** (`execution.py`):

- **DockerAdapter** — when Docker is available and a module carries an
  `execution` spec, the module's benign command runs for real inside a
  throwaway, **network-isolated** container (`--network none`, constrained
  memory/cpu/pids, `--no-new-privileges`, no host mounts, `--rm`). Its actual
  stdout/stderr, exit code, and timing are captured as timeline events. Five
  Linux/Docker modules ship with real execution specs (recon, Linux exec,
  Linux discovery, container discovery, container runtime).
- **SimulatedAdapter** — for modules without an execution spec (e.g. the
  Windows modules) or when Docker is down, the module emits the telemetry it
  *declares* it would produce. The system degrades gracefully to simulation.

Every timeline event's payload carries `real: true|false`, and the dashboard
tags each event **real** or **sim** so operators always know which is which.
This is the first cut of the spec's execution-adapter seam; the same interface
later drives agents on real VM targets (KVM/Proxmox/VMware), Phase 2.

## Detection engine (real rules, not a manual verdict)

When a module runs, the **detection engine** (`detection.py`) evaluates
versioned, Sigma-like rules (`seed/detections.json`) against the timeline —
including the *real* container output — and records verdicts automatically:

- **`log`-basis rules** regex-match real captured log lines (high fidelity),
  e.g. a rule fires on `spawning nested shell` or `uid=0(root)` produced by an
  actual container. These are marked `real` on the timeline.
- **`technique`-basis rules** provide coverage for behaviors that are simulated
  rather than executed in a container.

Each detection records **which rule fired, the matched evidence line, severity,
and latency (MTTD)** — the time from the activity to the verdict. Detections
appear on the shared timeline and feed the report's detected-coverage and
scoring. Blue can still add a manual verdict, but the baseline is automatic.

Kernel-level syscall detection (Falco) is the Phase-2 sensor; this engine is
its portable analog over collected telemetry — the same model a SIEM uses.

## Safety model

This platform emulates **observable adversary behavior inside owned lab
assets**. The catalog favors atomic, deterministic simulations and benign
stand-ins over live malware. Modules are signed and carry a safety class
(S0/S1/S2); the `Prohibited` class (self-propagation, external targeting,
real credential theft, live malware) is never executable. The service layer
enforces this: unsigned modules are refused, and S2 actions require
instructor/admin approval.
