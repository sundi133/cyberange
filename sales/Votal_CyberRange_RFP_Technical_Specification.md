# Votal AI — Cyber Range Technical Specification (RFP Input)

**Prepared for:** Cyber Range RFP — technical requirements input
**Author:** Votal AI
**Document status:** RFP-ready specification. Requirements are written to be
**demanding, measurable, and vendor-neutral**, and are anchored in Votal AI's
genuinely demonstrable capabilities so that every bar set here can be proven
live at proof-of-concept. Items on Votal AI's delivery roadmap are marked
**[Roadmap]** and are *not* presented as shipping capability.

---

## 0. How to read this document (and a note on fairness)

Each requirement is stated as a triplet so it can be scored objectively by any
evaluator and met by any capable bidder:

> **Requirement** (what the solution must do) → **Acceptance test** (the
> measurable pass/fail check) → **Evidence** (the artifact that proves it).

Two deliberate choices make this specification defensible and procurement-safe:

1. **Requirements describe operational and training *outcomes*, not one
   vendor's feature names.** Where a bar is set high, it is because the
   underlying operational need justifies it — not to exclude a competitor. A
   requirement tailored to a single product's datasheet is the most common
   reason a tender is challenged, re-run, or voided; this document avoids that.
2. **Everything demanded here is demonstrable at POC.** Votal AI sets the bar
   where it can clear it on the table, in front of the evaluator, with evidence.
   That is what makes the benchmark credible rather than aspirational.

Keyword convention: **MUST** = mandatory (non-compliance disqualifies on that
line); **SHOULD** = strongly preferred (scored, not disqualifying).

---

## 1. On-premises prerequisites

### 1.1 Compute, storage, and network sizing (tiered)

The solution MUST publish sizing tiers with concrete, testable figures so a
Purchaser can provision accurately. Votal AI's reference tiers:

| Tier | Compute | RAM | Storage | Network | Concurrent ranges |
|---|---|---|---|---|---|
| **Evaluation (simulated)** | 2 cores | 4 GB | ~2 GB | 1 GbE | 1–3 |
| **Single-node real execution** | 4 cores | 8–16 GB | 50 GB+ (image/evidence) | 1 GbE | 3–5 |
| **Full detection stack** | +4 cores | +4 GB (SIEM indexer) | +per-volume log storage | 1 GbE | as above |
| **VM tier (Windows/AD) [Roadmap]** | 8 vCPU, nested-virt | 32 GB | ~150 GB SSD | 1/10 GbE | 1–3 per node |
| **Team appliance** | 2–4 nodes | 256–512 GB/node | shared image/evidence store | 10/25 GbE | 5–20 |
| **Enterprise cluster** | HA control plane + elastic pools | per node above | shared store | 10/25 GbE | 20+ |

- **Req 1.1.1 — MUST** run the full control plane (catalog, lifecycle, scoring,
  reporting, audit) within a **2-core / 4 GB / 2 GB-disk** evaluation footprint.
  *Acceptance:* deploy on a 4 GB host, complete a simulated exercise end to end.
  *Evidence:* `/api/health` output + completed after-action report.
- **Req 1.1.2 — MUST** publish per-tier concurrent-range capacity and sustain
  the stated count without control-plane degradation. *Acceptance:* run N
  concurrent ranges at the quoted tier; median API response < 500 ms.
  *Evidence:* load-test transcript + range list.

### 1.2 Supported operating systems, hypervisors, databases, dependencies

- **Req 1.2.1 — MUST** run the control plane on any OS providing **Python
  3.10+** (Linux, macOS, Windows), with **no build step and no mandatory
  third-party runtime dependency**. *Acceptance:* clone and start with no
  package installation. *Evidence:* install transcript showing zero `pip`
  installs for the core.
- **Req 1.2.2 — MUST** support **SQLite** (zero-config default) **and
  PostgreSQL 14+** (production, incl. managed Postgres) behind one interface,
  switchable by connection string with **no code change**. *Acceptance:* same
  build runs on both; schema auto-creates on boot. *Evidence:* standalone
  `schema.sql` + a run against real Postgres.
- **Req 1.2.3 — MUST** execute real adversary behavior on a reachable
  **container runtime (Docker Engine / OCI)**; **SHOULD** integrate with a
  hypervisor (**KVM/Proxmox/VMware**) for full-VM Windows/Active Directory
  targets. *Status:* container tier shipping; **VM/AD tier [Roadmap]** via a
  defined topology/adapter seam — stated as roadmap, not shipping.
- **Req 1.2.4 — MUST** enumerate every third-party component and its license
  (see §1.4). Core dependency surface MUST be **standard-library only**.

### 1.3 Connectivity and installation

- **Req 1.3.1 — MUST** install as a **single service** (container image or
  stdlib process) exposing one HTTP(S) port. *Acceptance:* `docker compose up`
  or `make serve` yields a working dashboard + API. *Evidence:* running URL.
- **Req 1.3.2 — MUST** reject unauthenticated API access by default and MUST
  NOT enable any developer identity shortcut unless explicitly configured.
  *Acceptance:* unauthenticated call returns `401`. *Evidence:* request log.

### 1.4 Licensing

- **Req 1.4.1 — MUST** require **no paid third-party runtime license** for the
  shipping Linux/Docker path. Control plane = Python stdlib + SQLite; detection
  stack (Wazuh, Sysmon, Suricata, Zeek, osquery) and imported content (Atomic
  Red Team MIT, CALDERA Apache-2.0) are open source. *Evidence:* license
  inventory table.
- **Req 1.4.2 — MUST** state clearly that the **only** customer-supplied paid
  licensing is **Microsoft Windows/AD media** for the [Roadmap] VM tier; the
  platform ships no Windows media. *Rationale:* honesty here prevents a
  post-award licensing surprise.

### 1.5 Isolated / air-gapped environments

- **Req 1.5.1 — MUST** install and operate fully **offline / air-gapped**: no
  outbound connectivity required at install or runtime for the core platform.
  *Acceptance:* install from a local artifact bundle on a host with egress
  blocked; run a full exercise. *Evidence:* exercise completed with network
  egress denied at the host firewall.
- **Req 1.5.2 — MUST** default ranges to **egress-deny** and keep the control
  plane on a network unreachable from tenant/lab workloads. *Acceptance:*
  attempt outbound from inside a provisioned range → blocked. *Evidence:*
  network policy + blocked-connection log.

---

## 2. Deployment architecture

The solution MUST offer **both** an on-premises/self-hosted model and a
managed/SaaS model from **one codebase**, so capability does not fork between
them. Differences MUST be limited to who operates the infrastructure, not what
the platform can do.

### 2.1 On-premises / customer-hosted model

- **Req 2.1.1 — MUST** give the Purchaser **full ownership of all data and lab
  assets**, deployable on customer Docker/hypervisor infrastructure, including
  air-gapped (per §1.5).
- **Req 2.1.2 — Scalability — MUST** scale from a single node to a multi-node
  hypervisor cluster with elastic execution pools. **SHOULD** scale the control
  plane horizontally behind a load balancer with a shared Postgres backend.
- **Req 2.1.3 — Concurrent users — MUST** support role-separated concurrent
  participants (red/blue/purple/instructor/observer) per range and multiple
  concurrent ranges per the §1.1 tiers. *Acceptance:* quoted concurrent-user
  count demonstrated. *Evidence:* live multi-session test.
- **Req 2.1.4 — Availability — SHOULD** support an HA control-plane topology
  (stateless app tier + replicated Postgres) with a stated SLA target.
- **Req 2.1.5 — Backup/DR — MUST** support consistent backup of all state
  (single SQLite file *or* standard Postgres dump/PITR). *Acceptance:* back up,
  restore to a clean host, resume operations with evidence intact. *Evidence:*
  restore transcript + hash-verified evidence timeline. **Target: RPO ≤ 24 h,
  RTO ≤ 4 h** on the reference tier (tighter with Postgres PITR).
- **Req 2.1.6 — Upgrades/maintenance — MUST** apply schema migrations
  automatically on boot (`CREATE TABLE IF NOT EXISTS`-class, forward-compatible)
  and MUST document a rollback path. **Maintenance RACI MUST be published** (see
  §2.3).

### 2.2 SaaS / managed model

- **Req 2.2.1 — MUST** offer a hosted control plane with managed TLS and a
  managed Postgres backend, provisionable without customer infrastructure.
- **Req 2.2.2 — MUST** state the hosted-tier execution caveat **plainly**: a
  hosted app container without a Docker daemon runs modules in **simulation**
  (technique-basis detection); **real container execution requires a Docker
  host**, commonly the light control plane hosted with an execution host
  alongside. *Rationale:* no hidden fidelity gap post-sale.
- **Req 2.2.3 — Scalability/availability — SHOULD** provide managed scaling,
  backup, and availability as an operator responsibility with a published SLA.
- **Req 2.2.4 — Data residency — MUST** allow selection of hosting
  region/jurisdiction for the managed tier (see §4.5).

### 2.3 Maintenance responsibility (RACI)

The solution MUST publish a responsibility split. Votal AI's model:

| Activity | On-prem | SaaS |
|---|---|---|
| Infrastructure / OS patching | Purchaser | Votal AI |
| Platform upgrades | Purchaser (assisted) | Votal AI |
| Backup execution & DR drills | Purchaser | Votal AI (Purchaser verifies) |
| Content library updates | Votal AI (delivered) | Votal AI |
| User & role administration | Purchaser | Purchaser |
| Lab asset / target lifecycle | Purchaser | Shared |

---

## 3. Cyber range capabilities

Unifying requirement — **Req 3.0 — MUST** deliver **red, blue, and purple** team
exercises, **solo guided** exercises (one learner runs both attacker and
defender phases on one timeline), and **purple detection sprints** from a
**single platform**, with no separate product, environment, or license per mode.

### 3.1 Scenario creation and customisation

- **Req 3.1.1 — MUST** ship a populated, versioned scenario/TTP catalog
  **mapped to MITRE ATT&CK**, searchable/filterable by role, tactic, technique,
  difficulty, platform, and safety class. *Current build:* 10+ launch scenarios
  spanning introductory→advanced, including a full **ransomware kill chain** and
  a **cloud intrusion kill chain**; **13 of 14 Enterprise tactics** covered.
  *Acceptance:* catalog returns scenarios with ATT&CK mappings. *Evidence:*
  `/api/scenarios`, `/api/tactics`, `/api/frameworks`.
- **Req 3.1.2 — MUST** let a customer **author their own scenarios/modules** from
  a compact declarative config **without vendor engineering**, and MUST require
  authored executable content to be **cryptographically signed** before it can
  run. *Acceptance:* author a new scenario, sign it, launch it. *Evidence:*
  authored config + signature + run.
- **Req 3.1.3 — MUST** support declarative **topology templates** (VM / network
  / identity) bound to each scenario. *Evidence:* `/api/topologies`.

### 3.2 Attack & defence simulation (fidelity)

- **Req 3.2.1 — MUST** execute adversary behavior as **genuine commands inside
  isolated targets**, capturing **actual stdout, stderr, exit code, and timing**
  as telemetry — not pre-recorded transcripts. Atomic execution containers MUST
  be **network-isolated (`--network none`)**, memory/CPU/PID-capped, started
  **`--no-new-privileges`**, given **no host mounts**, removed on exit, and
  bounded by a **60–600 s per-module timeout**. *Acceptance:* run a module;
  inspect captured real output and the enforced container constraints.
  *Evidence:* timeline event with `real: true` + container run spec.
- **Req 3.2.2 — MUST** support **persistent, connected live ranges** where a
  foothold established in one step survives into the next and targets are
  mutually reachable across a per-range **no-egress** internal network — a real
  kill chain, not disconnected atomic actions. Identity scenarios MUST stand up
  a **real directory** seeded with synthetic users for genuine enumeration
  (T1087). *Acceptance:* multi-step chain demonstrates persistence + lateral
  reachability. *Evidence:* timeline across steps.
- **Req 3.2.3 — MUST** degrade gracefully: where the execution tier is
  unavailable or a module has no execution spec, fall back to a **simulated
  adapter** that emits declared telemetry rather than failing the exercise, and
  MUST **label every timeline event `real` or `sim`** so fidelity is never in
  doubt. *Acceptance:* disable Docker; exercise still runs, scores, reports, and
  labels events `sim`. *Evidence:* mixed-mode timeline.
- **Req 3.2.4 — Safety — MUST** classify every executable item (S0 simulation /
  S1 atomic emulation / S2 high-impact lab action / **Prohibited**), enforce
  approval authority **in the execution path** (not by policy document), refuse
  **unsigned** modules at execution, and make **Prohibited** behavior
  (self-propagation, external targeting, real credential theft, live malware)
  **non-executable by any role including admin**. High-impact actions MUST be
  scoped to lab canaries (e.g. ransomware impact encrypts canary files only).
  *Acceptance:* attempt an unsigned/prohibited/over-privileged action → refused.
  *Evidence:* refusal + audit entry.

### 3.3 Training environments & orchestration

- **Req 3.3.1 — MUST** manage range lifecycle as an enforced **state machine**
  (request→preflight→provision→seed→ready→running⇄paused→completing→evidence-locked→archived→destroyed,
  plus **QUARANTINED** with **admin-only release**), rejecting illegal
  transitions with `409`. *Evidence:* lifecycle API + rejected transition.
- **Req 3.3.2 — MUST** provide an integrated **learning platform** (classes,
  CSV roster bulk-enrol, assignments, guided lessons with auto-graded quizzes,
  per-student gradebook export) so no external LMS is required, while **SHOULD**
  exposing the full API for LMS/ticketing integration.

### 3.4 Observation, assessment & reporting

- **Req 3.4.1 — MUST** record all activity on one **synchronized UTC timeline
  with integrity hashes**, shared across roles, **lockable** at completion for an
  immutable after-action/accreditation record.
- **Req 3.4.2 — Fog of war — MUST** present defenders a **redacted** SOC-style
  log search: technique attribution, module IDs, command lines, and safety
  metadata stripped, event source relabelled to the **affected asset**.
  Redaction MUST be enforced at the **query layer**, not by asking participants
  not to look. *Acceptance:* blue view contains no attacker attribution.
  *Evidence:* side-by-side operator vs. defender query results.
- **Req 3.4.3 — Detection — MUST** auto-evaluate **versioned, Sigma-style rules**
  against real telemetry, recording **which rule fired, the matched evidence
  line, severity, and MTTD** without human input, with a manual-verdict path on
  top. *Evidence:* detection record with rule id + MTTD.
- **Req 3.4.4 — Scoring — MUST** produce an **explainable weighted score**
  across red execution, detection, investigation, response, and collaboration,
  returning every dimension's raw score, weight, and contribution, with
  penalties and **every instructor override audited** (named approver +
  justification). A derived score MUST exist from observed activity before any
  human judgement. *Evidence:* score breakdown + override audit.
- **Req 3.4.5 — Purple — MUST** report purple exercises as a **baseline-to-replay
  coverage delta per technique**, never win/lose.
- **Req 3.4.6 — Reporting — MUST** export after-action reports (coverage, gaps,
  evidence inventory, recommendations) in **JSON, CSV, HTML, and DOCX**.
  *Evidence:* the four exports.

### 3.5 Integrations

- **Req 3.5.1 — MUST** ship optional **real SIEM** integration (bundled Wazuh:
  manager, indexer, dashboard) that ingests normalized event JSON, raises
  genuine alerts from platform rules, and posts them back to the exercise
  timeline. The telemetry contract MUST be **normalized** so Elastic / Sentinel
  / Splunk substitution is an adapter exercise, not a redesign. *Evidence:*
  Wazuh alert appearing as a timeline detection.
- **Req 3.5.2 — MUST** expose a complete **REST/JSON API** (bearer auth) for
  every dashboard action, with structured status codes (400/401/403/404/409/500).

---

## 4. Security and administration

### 4.1 Access controls (RBAC)

- **Req 4.1.1 — MUST** enforce role→permission mapping **server-side on every
  API call**, with distinct roles (admin, instructor, red, blue, purple, solo,
  read-only security leader) and least-privilege separation — e.g. red cannot
  execute S2; blue cannot execute attacker modules; only admin releases
  quarantine. *Acceptance:* each role blocked from out-of-scope actions.
  *Evidence:* live permission matrix (`/api/roles`) + denied-action logs.

### 4.2 Authentication

- **Req 4.2.1 — MUST** store passwords as **PBKDF2-HMAC-SHA256 with a per-user
  random salt** (never plaintext), issue **opaque session tokens with a bounded
  TTL (≤ 12 h)**, return **non-enumerating** login errors, and **immediately
  revoke all sessions** when a user is disabled. *Evidence:* auth config + a
  disable-then-denied test.
- **Req 4.2.2 — SHOULD** support **SSO/OIDC** with the RBAC layer unchanged.
  *Status:* **[Roadmap]** — identity swap only, isolated from permissions.

### 4.3 Tenant isolation

- **Req 4.3.1 — MUST** isolate ranges on per-range **no-egress** networks, label
  every artifact by range ID, run all execution **non-privileged and
  resource-capped**, and keep the control plane unreachable from tenant
  workloads. *Acceptance:* cross-range reachability test fails. *Evidence:*
  network policy + test log.

### 4.4 Encryption

- **Req 4.4.1 — MUST** serve all remote access over **TLS** (managed on hosted
  tiers; Purchaser-terminated on-prem). **MUST** support encryption at rest for
  the datastore (Postgres TDE / disk encryption; SQLite on an encrypted volume).
  *Evidence:* TLS config + at-rest encryption attestation.

### 4.5 Audit logs & data residency

- **Req 4.5.1 — MUST** write every state change to an **append-only audit
  ledger** readable by admins, covering lifecycle, execution, overrides, and
  user management. *Evidence:* `/api/audit` output.
- **Req 4.5.2 — MUST** keep all data within Purchaser-controlled infrastructure
  on-prem, and MUST allow **region/jurisdiction selection** on the managed tier.

### 4.6 Monitoring & administrative controls

- **Req 4.6.1 — MUST** expose a health endpoint reporting execution mode and
  component status, and MUST provide admin controls for user provisioning, image
  management, **emergency pause/kill**, quarantine release, and score override.
  *Evidence:* `/api/health` + admin panel walkthrough.

---

## 5. Acceptance criteria, demonstration & proof-of-concept

All benchmarks below MUST be demonstrated **live at POC** on Purchaser-witnessed
infrastructure, with the named evidence artifact produced on the spot. These are
set where Votal AI can clear them in front of the evaluator.

### 5.1 Measurable performance benchmarks

| # | Benchmark | Pass criterion | Evidence |
|---|---|---|---|
| B1 | Install footprint | Full control plane runs on 2-core/4 GB/2 GB-disk | `/api/health` + completed exercise |
| B2 | Air-gapped install | Install + full exercise with host egress blocked | Firewall log + report |
| B3 | Deploy time | Running dashboard + API from a clean host in **≤ 30 min** | Timed install transcript |
| B4 | Real execution fidelity | Module captures genuine stdout/stderr/exit/timing in a network-isolated, capped, non-privileged, no-mount, auto-removed container | Timeline event `real:true` + run spec |
| B5 | Graceful degradation | With Docker disabled, exercise still runs, scores, reports, labels events `sim` | Mixed-mode timeline |
| B6 | Fog-of-war redaction | Defender view contains zero attacker attribution/command lines | Operator vs. defender query diff |
| B7 | Auto-detection + MTTD | Rule fires automatically on real output; MTTD recorded | Detection record |
| B8 | Explainable scoring | Score returns per-dimension raw/weight/contribution + audited overrides | Score breakdown |
| B9 | Concurrency | Sustain quoted concurrent ranges/users; median API latency **< 500 ms** | Load-test transcript |
| B10 | Backup/restore | Restore to a clean host; evidence hashes verify; resume ops (**RPO ≤ 24 h, RTO ≤ 4 h**) | Restore transcript |
| B11 | Safety enforcement | Unsigned/prohibited/over-privileged action refused **in the execution path** | Refusal + audit entry |
| B12 | Reporting formats | After-action report exports in JSON, CSV, HTML, DOCX | Four files |
| B13 | Customer authoring | Evaluator authors, signs, and runs a new scenario without vendor code | Authored config + run |
| B14 | Portability | Switch SQLite→Postgres and built-in detection→real SIEM by configuration only | Both backends + Wazuh alert |

### 5.2 Demonstration requirements

- **Req 5.2.1 — MUST** run a **live red→blue exercise** end to end: red executes a
  real technique; blue hunts it in the redacted SOC search with no foreknowledge;
  detection fires; score and after-action report are produced.
- **Req 5.2.2 — MUST** demonstrate the **governance path**: unsigned-module
  refusal, S2 gating, quarantine + admin-only release, and the audit ledger.

### 5.3 Supporting evidence (with the bid)

- **Req 5.3.1 — MUST** supply an automated **test suite that runs on the standard
  library with no external services** (tests needing Docker/Postgres skip
  cleanly), and report pass counts. *Current build:* 130+ tests across API,
  lifecycle, detection, execution adapters, scoring, redaction, and persistence.
- **Req 5.3.2 — MUST** supply the **live capability counts via the catalog API**
  (scenarios, modules, real-execution modules, techniques, detection rules) so
  claimed numbers are **independently verifiable**, not asserted in prose.

### 5.4 Proposed POC test plan (2–3 days, witnessed)

1. **Day 1 — Deploy & air-gap:** B1, B2, B3; walk the lifecycle state machine.
2. **Day 2 — Fidelity & defence:** B4–B8 via a live red→blue exercise; B11 governance.
3. **Day 3 — Operate & verify:** B9 concurrency, B10 backup/restore, B12 reporting,
   B13 customer authoring, B14 portability; verify B counts against the catalog API.

**Scoring:** each MUST is pass/fail; each SHOULD is weighted. A bidder claiming
compliance on any requirement MUST evidence it live or disclose it as roadmap —
the same standard Votal AI holds itself to in this document.

---

*This specification was prepared from Votal AI's shipping CyberRange build.
Capability counts reflect the current catalog and are verifiable through the
platform's own API; roadmap items are labelled and are not claimed as shipping.*
