# Votal AI — Cyber Range Technical Specification (RFP Input)

**Prepared for:** Cyber Range RFP — technical requirements input
**Author:** Votal AI
**Document status:** RFP-ready specification describing the Votal AI CyberRange
**platform as delivered**. Requirements are stated to be demanding, measurable,
and vendor-neutral, and every bar is anchored in a capability Votal AI stands
behind contractually.

**Delivery-status legend (used on every requirement):**

| Tag | Meaning | How it is accepted |
|---|---|---|
| **GA** | In the current build; operates in the Purchaser's environment on day one | Demonstrated live at POC |
| **P1** | Committed Phase-1 deliverable, delivered and accepted at contract go-live | Accepted at a staged go-live milestone against the same acceptance test |

Both GA and P1 are contractual capabilities Votal AI is bound to deliver. The
only difference is *when* the Purchaser witnesses the acceptance test — at POC
(GA) or at the go-live milestone (P1). Nothing in this document is aspirational.

---

## 0. How to read this document

Each requirement is a triplet so it can be scored objectively by any evaluator
and met by any capable bidder:

> **Requirement** (what the solution does) → **Acceptance test** (the
> measurable pass/fail check) → **Evidence** (the artifact that proves it).

Two deliberate choices keep this specification both demanding and
procurement-safe:

1. **Requirements describe operational and training *outcomes*, not one vendor's
   feature names.** Where a bar is high, the underlying operational need
   justifies it. A requirement written to a single product's datasheet is the
   most common reason a tender is challenged, re-run, or voided; this document
   avoids that while still setting a bar most bidders will struggle to clear.
2. **Every claim is verifiable.** GA capabilities are demonstrated live and
   their counts are read back from the platform's own API, not asserted in
   prose. P1 capabilities are accepted against the identical test at go-live.

Keyword convention: **MUST** = mandatory (non-compliance disqualifies on that
line); **SHOULD** = strongly preferred (scored, not disqualifying).

---

## 1. On-premises prerequisites

### 1.1 Compute, storage, and network sizing

The solution MUST publish sizing tiers with concrete, testable figures and a
**per-range resource model** so a Purchaser can provision precisely rather than
by guesswork.

**Reference tiers**

| Tier | Compute | RAM | Storage | Network | Concurrent ranges | Delivery |
|---|---|---|---|---|---|---|
| Evaluation (simulated) | 2 cores | 4 GB | ~2 GB | 1 GbE | 1–3 | GA |
| Single-node real execution | 4 cores | 8–16 GB | 50 GB+ | 1 GbE | 3–5 | GA |
| Full detection stack (+SIEM) | +4 cores | +4 GB | + log volume | 1 GbE | per node | GA |
| VM tier (Windows/AD) | 8 vCPU (nested-virt) | 32 GB | ~150 GB SSD/node | 1/10 GbE | 1–3 per node | P1 |
| Team appliance | 2–4 nodes | 256–512 GB/node | shared image+evidence store | 10/25 GbE | 5–20 | P1 |
| Enterprise cluster | HA control plane + elastic exec pools | per node above | shared store (NFS/S3-compatible) | 10/25 GbE | 20+ | P1 |

**Per-range resource model (for capacity planning)**

- Control plane: **~256 MB RAM + <1 vCPU** steady state per node (stdlib HTTP
  server + datastore client); scales with API request rate, not range count.
- Atomic container run: bounded by the module's own caps (default **≤512 MB
  RAM, ≤1 vCPU, ≤256 PIDs**, 60–600 s lifetime), reclaimed on exit.
- Live connected range: **~1–2 GB RAM + 1–2 vCPU** for the per-range network and
  persistent hosts; directory-backed identity scenarios add **~512 MB** for the
  synthetic directory.
- Evidence/log storage: **~5–50 MB per completed exercise** (timeline + captured
  output + detections), linear in exercise length and module count.

Requirements:

- **Req 1.1.1 (GA) — MUST** run the full control plane (catalog, lifecycle,
  scoring, reporting, audit) within a **2-core / 4 GB / 2 GB-disk** footprint.
  *Acceptance:* deploy on a 4 GB host; complete a simulated exercise end to end.
  *Evidence:* `/api/health` + completed after-action report.
- **Req 1.1.2 (GA) — MUST** publish per-tier concurrent-range capacity and
  sustain the stated count with **median control-plane API latency < 500 ms and
  p95 < 1500 ms**. *Acceptance:* drive N concurrent ranges at the quoted tier.
  *Evidence:* load-test transcript + range list.
- **Req 1.1.3 (GA) — MUST** cap every execution artifact (RAM, CPU, PID count,
  wall-clock) and reclaim it deterministically, so range count cannot exhaust
  the host. *Acceptance:* launch to the tier limit; confirm reclaim on
  completion. *Evidence:* host resource trace across the run.

### 1.2 Supported operating systems, hypervisors, databases, dependencies

- **Req 1.2.1 (GA) — MUST** run the control plane on any OS providing **Python
  3.10+** (Linux — RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 11+; macOS 12+;
  Windows Server 2019+), with **no build step and no mandatory third-party
  runtime dependency**. *Acceptance:* clone and start with zero package
  installation. *Evidence:* install transcript showing no `pip` install for the
  core.
- **Req 1.2.2 (GA) — MUST** support **SQLite** (zero-config default) **and
  PostgreSQL 14+** (production, including managed Postgres) behind one storage
  interface, switchable by connection string with **no code change**, schema
  auto-created on boot, verified against real Postgres in the test suite.
  *Acceptance:* same build on both backends. *Evidence:* standalone `schema.sql`
  (with optional row-level security) + a run against real Postgres.
- **Req 1.2.3 — MUST** execute real adversary behavior on a reachable
  **container runtime (Docker Engine 20.10+ / OCI)** *(GA)*, and MUST integrate
  with a **hypervisor (KVM/Proxmox VE 8+/VMware ESXi 7+)** for full-VM
  Windows/Active Directory targets *(P1)* through a declarative
  topology/provisioner interface. *Acceptance:* container tier demonstrated at
  POC; VM/AD tier accepted at go-live against the same execution-fidelity test.
- **Req 1.2.4 (GA) — MUST** enumerate every third-party component and its
  license (see §1.4); the core dependency surface MUST be **standard-library
  only** (the optional `psycopg` Postgres driver and `PyYAML` for YAML authoring
  are the only add-ons, both shipped in the container image).

**Dependency inventory (core path)**

| Component | Role | Dependency |
|---|---|---|
| Control plane | API, lifecycle, scoring, reporting, audit | Python 3.10+ stdlib only |
| Datastore | persistence | SQLite (stdlib) or PostgreSQL + `psycopg` |
| Execution | real runs | Docker Engine / OCI runtime |
| SIEM (optional) | real alerting | Wazuh (manager/indexer/dashboard) |
| Authoring (optional) | YAML scenario configs | `PyYAML` (JSON needs nothing) |

### 1.3 Connectivity and installation

- **Req 1.3.1 (GA) — MUST** install as a **single service** (container image or
  stdlib process) exposing one HTTP(S) port, with configuration by environment
  variable only (no config-file sprawl). *Acceptance:* `docker compose up` or a
  single start command yields a working dashboard + API in **≤ 30 minutes** from
  a clean host. *Evidence:* timed install transcript + running URL.
- **Req 1.3.2 (GA) — MUST** reject unauthenticated API access by default and
  MUST NOT enable any developer identity shortcut unless explicitly configured.
  *Acceptance:* unauthenticated call returns `401`. *Evidence:* request log.
- **Req 1.3.3 (GA) — MUST** document every listening port, every outbound
  connection the platform makes (the core path makes **none**), and the exact
  firewall posture required. *Evidence:* port/flow table.

### 1.4 Licensing

- **Req 1.4.1 (GA) — MUST** require **no paid third-party runtime license** for
  the shipping Linux/Docker path: control plane = Python stdlib + SQLite;
  detection stack (Wazuh, Sysmon, Suricata, Zeek, osquery) and imported content
  (Atomic Red Team — MIT; MITRE CALDERA — Apache-2.0) are open source.
  *Evidence:* license inventory table.
- **Req 1.4.2 — MUST** state plainly that the **only** customer-supplied paid
  licensing is **Microsoft Windows/AD media** for the VM tier *(P1)*; the
  platform ships no Windows media and relies on the Purchaser's evaluation or
  volume licensing. *Rationale:* disclosing this up front prevents a post-award
  licensing dispute.
- **Req 1.4.3 (GA) — MUST** impose no per-seat or per-exercise metering that
  requires outbound license check-in, so an air-gapped deployment is never
  license-blocked.

### 1.5 Isolated / air-gapped environments

- **Req 1.5.1 (GA) — MUST** install and operate fully **offline / air-gapped**:
  no outbound connectivity required at install or runtime for the core platform.
  *Acceptance:* install from a local artifact bundle on a host with egress
  blocked at the firewall; run a full exercise. *Evidence:* firewall log showing
  zero egress + completed report.
- **Req 1.5.2 (GA) — MUST** provide an **offline artifact bundle** (platform
  image, signed content pack, container base images, optional SIEM images) that
  loads into a local registry with no internet access, plus a documented
  checksum/signature verification step. *Evidence:* bundle manifest + load
  transcript.
- **Req 1.5.3 (GA) — MUST** default ranges to **egress-deny** and keep the
  control plane on a network unreachable from tenant/lab workloads.
  *Acceptance:* attempt outbound from inside a provisioned range → blocked.
  *Evidence:* network policy + blocked-connection log.

---

## 2. Deployment architecture

The solution MUST offer **both** an on-premises/self-hosted model and a
managed/SaaS model from **one codebase**, so capability never forks between
them. Differences MUST be limited to who operates the infrastructure, not what
the platform can do.

### 2.1 On-premises / customer-hosted model

- **Req 2.1.1 (GA) — MUST** give the Purchaser **full ownership of all data and
  lab assets**, deployable on customer Docker/hypervisor infrastructure,
  including air-gapped (per §1.5).
- **Req 2.1.2 — Scalability — MUST** scale from a single node to a multi-node
  hypervisor cluster with elastic execution pools *(team/enterprise tiers:
  P1)*, and the **stateless control plane MUST scale horizontally behind a load
  balancer with a shared PostgreSQL backend** *(GA — the app tier holds no local
  session state beyond the datastore)*. *Acceptance:* run two control-plane
  replicas against one Postgres; sessions and ranges are consistent across both.
  *Evidence:* dual-replica test transcript.
- **Req 2.1.3 — Concurrent users — MUST** support role-separated concurrent
  participants (red / blue / purple / instructor / observer) per range and
  multiple concurrent ranges per the §1.1 tiers. *Acceptance:* the quoted
  concurrent-user count demonstrated with live sessions. *Evidence:* multi-session
  test.
- **Req 2.1.4 — Availability — MUST** support an HA control-plane topology
  (stateless app replicas + replicated Postgres) with a **target of 99.5%
  monthly availability** for the control plane, excluding Purchaser
  infrastructure outages *(HA topology: P1; stateless app tier enabling it:
  GA)*. *Evidence:* HA deployment diagram + failover test.
- **Req 2.1.5 — Backup/DR — MUST** support consistent backup and restore of all
  state. *Acceptance:* back up (single SQLite file **or** Postgres
  `pg_dump`/PITR), restore to a clean host, resume operations with the evidence
  timeline's integrity hashes intact. **Targets: RPO ≤ 24 h, RTO ≤ 4 h** on the
  reference tier; **RPO ≤ 15 min** with Postgres PITR/WAL archiving.
  *Evidence:* restore transcript + hash-verified evidence timeline. *(GA for
  SQLite + Postgres dump; PITR topology: P1.)*
- **Req 2.1.6 — Upgrades/maintenance — MUST** apply forward-compatible schema
  migrations automatically on boot, support a documented rollback to the prior
  image, and perform routine platform upgrades with **no loss of locked
  evidence**. *Acceptance:* upgrade across a schema change; prior exercises and
  their locked evidence remain readable. *Evidence:* upgrade transcript. *(GA.)*

### 2.2 SaaS / managed model

- **Req 2.2.1 (GA) — MUST** offer a hosted control plane with managed TLS and a
  managed PostgreSQL backend, provisionable without any Purchaser
  infrastructure.
- **Req 2.2.2 (GA) — MUST** state the hosted-execution model **plainly**: a
  hosted application container without a co-located Docker host runs modules in
  **simulation** with technique-basis detection; **real container execution
  requires a reachable Docker host**, which the managed tier provisions
  alongside the control plane. *Rationale:* no hidden fidelity gap discovered
  after purchase.
- **Req 2.2.3 — Managed scaling/availability — MUST** provide scaling, backup,
  patching, and availability as a Votal AI operator responsibility under a
  **published SLA (target 99.5% monthly)**, with the Purchaser retaining data
  export rights at any time. *(Managed tier operation: P1; export: GA.)*
- **Req 2.2.4 — Data residency — MUST** allow selection of hosting
  region/jurisdiction at provisioning time and MUST NOT move Purchaser data out
  of the selected region (see §4.5). *(P1.)*

### 2.3 Maintenance responsibility (RACI)

| Activity | On-prem | SaaS |
|---|---|---|
| Infrastructure / OS patching | Purchaser | Votal AI |
| Platform upgrades | Purchaser (Votal AI-assisted, documented) | Votal AI |
| Backup execution & DR drills | Purchaser (procedure + tooling supplied) | Votal AI (Purchaser verifies) |
| Content library updates | Votal AI (signed packs delivered) | Votal AI |
| Scenario/content authoring | Purchaser + Votal AI | Purchaser + Votal AI |
| User & role administration | Purchaser | Purchaser |
| Lab asset / target lifecycle | Purchaser | Shared |
| Security monitoring of the platform | Purchaser | Votal AI |

---

## 3. Cyber range capabilities

**Req 3.0 (GA) — MUST** deliver **red, blue, and purple** team exercises,
**solo guided** exercises (one learner runs both attacker and defender phases on
one timeline), and **purple detection sprints** from a **single platform**, with
no separate product, environment, or license per mode.

### 3.1 Scenario creation and customisation

- **Req 3.1.1 (GA) — MUST** ship a populated, versioned scenario/TTP catalog
  **mapped to MITRE ATT&CK**, searchable and filterable by role, tactic,
  technique, difficulty, platform, and safety class. *Current build:* a catalog
  spanning introductory→advanced difficulty and **13 of 14 Enterprise ATT&CK
  tactics**, including a full **ransomware kill chain** (recon → persistence →
  discovery → collection → inhibit-recovery → service-stop → canary-impact →
  ransom-note) and a **cloud intrusion kill chain** (metadata-credential theft →
  account manipulation → cross-bucket collection → external-storage exfil →
  mailbox-rule and OAuth-consent footholds). *Acceptance:* catalog returns
  scenarios with ATT&CK mappings and the live counts. *Evidence:*
  `/api/scenarios`, `/api/tactics`, `/api/frameworks`.
- **Req 3.1.2 (GA) — MUST** let a Purchaser **author their own scenarios and
  behavior modules from a compact declarative config without vendor
  engineering**, and MUST require authored executable content to be
  **cryptographically signed** before it can run; unsigned content is refused at
  execution. *Acceptance:* evaluator authors a new scenario, signs it, launches
  it. *Evidence:* authored config + signature record + run.
- **Req 3.1.3 (GA) — MUST** bind each scenario to a declarative **topology
  template** (VM / network / identity), versioned with the scenario.
  *Evidence:* `/api/topologies`.
- **Req 3.1.4 (GA) — MUST** support **content import** from Atomic Red Team and
  MITRE CALDERA, with imported content **unsigned and non-executable until a
  reviewer signs it** (a reviewer sign workflow). *Evidence:* import →
  review → sign → run transcript.

### 3.2 Attack & defence simulation (fidelity)

- **Req 3.2.1 (GA) — MUST** execute adversary behavior as **genuine commands
  inside isolated targets**, capturing **actual stdout, stderr, exit code, and
  timing** as telemetry — never pre-recorded transcripts. Atomic execution
  containers MUST be **network-isolated (`--network none`)**, memory/CPU/PID-
  capped, started **`--no-new-privileges`**, given **no host mounts**, removed on
  exit (`--rm`), and bounded by a **60–600 s per-module timeout**. *Acceptance:*
  run a module; inspect captured real output and enforced constraints.
  *Evidence:* timeline event with `real: true` + container run spec.
- **Req 3.2.2 (GA) — MUST** support **persistent, connected live ranges** where
  a foothold established in one step survives into the next and targets are
  mutually reachable across a per-range **no-egress** internal network — a real
  kill chain, not disconnected atomic actions. Identity scenarios MUST stand up a
  **real directory seeded with synthetic users** for genuine enumeration
  (T1087). *Acceptance:* a multi-step chain demonstrates persistence + lateral
  reachability. *Evidence:* cross-step timeline.
- **Req 3.2.3 — MUST** provide **full-VM Windows and Active Directory targets**
  (real domain controller, Kerberos, SMB, GPO) for AD attack-path exercises via
  the hypervisor provisioner. *(P1 — accepted at go-live against a live
  AD-enumeration-and-attack exercise; the container tier's directory stand-in is
  the GA equivalent for Linux identity.)*
- **Req 3.2.4 (GA) — MUST** degrade gracefully: where the execution tier is
  unavailable or a module carries no execution spec, fall back to a **simulated
  adapter** that emits declared telemetry rather than failing the exercise, and
  MUST **label every timeline event `real` or `sim`** so fidelity is never in
  doubt. *Acceptance:* disable the execution host; the exercise still runs,
  scores, reports, and labels events `sim`. *Evidence:* mixed-mode timeline.
- **Req 3.2.5 (GA) — Safety — MUST** classify every executable item (**S0**
  simulation / **S1** atomic emulation / **S2** high-impact lab action /
  **Prohibited**), enforce approval authority **in the execution path** (not by
  policy document), refuse **unsigned** modules at execution, and make
  **Prohibited** behavior (self-propagation, external targeting, real credential
  theft, live malware) **non-executable by any role including admin**.
  High-impact actions MUST be scoped to lab canaries (e.g. ransomware impact
  encrypts **canary files only**). *Acceptance:* attempt an unsigned / prohibited
  / over-privileged action → refused. *Evidence:* refusal + audit entry.

### 3.3 Training environments & orchestration

- **Req 3.3.1 (GA) — MUST** manage range lifecycle as an **enforced state
  machine** — requested → preflight → provisioning → seeding → ready → running ⇄
  paused → completing → evidence-locked → archived → destroyed, plus
  **QUARANTINED with admin-only release** — rejecting illegal transitions with
  `409`. *Evidence:* lifecycle API + a rejected transition.
- **Req 3.3.2 (GA) — MUST** auto-quarantine any anomalous workload and allow
  only an administrator to release or destroy it, and MUST provide
  **emergency pause/kill** across a range. *Evidence:* quarantine + release
  audit trail.
- **Req 3.3.3 (GA) — MUST** provide an integrated **learning platform**: classes,
  CSV roster bulk-enrolment (generated passwords returned for distribution),
  assignments, guided lessons (briefing, concepts, ordered hands-on steps that
  run a real or simulated module on the learner's own auto-provisioned range),
  and **auto-graded knowledge checks** with per-student gradebook export — so no
  external LMS is required. **SHOULD** also expose the full API for LMS/ticketing
  integration. *Evidence:* class → roster → assignment → gradebook CSV.

### 3.4 Observation, assessment & reporting

- **Req 3.4.1 (GA) — MUST** record all activity on one **synchronized UTC
  timeline with per-event integrity hashes**, shared across roles, **lockable at
  completion** for an immutable after-action / accreditation record. *Evidence:*
  locked timeline + hash verification.
- **Req 3.4.2 (GA) — Fog of war — MUST** present defenders a **redacted**
  SOC-style log search: technique attribution, module IDs, command lines, safety
  class, and adapter metadata stripped, and the event source relabelled from
  attacker tooling to the **affected asset** (e.g. `host:victim`). Redaction MUST
  be enforced at the **query layer**, not by asking participants not to look.
  *Acceptance:* the defender view contains no attacker attribution. *Evidence:*
  side-by-side operator vs. defender query results.
- **Req 3.4.3 (GA) — Detection — MUST** auto-evaluate **versioned, Sigma-style
  rules** against real telemetry (including captured container output), recording
  **which rule fired, the matched evidence line, severity, and the latency from
  activity to verdict (MTTD)** without human input, with a manual-verdict path on
  top. *Evidence:* detection record with rule id, matched line, severity, MTTD.
- **Req 3.4.4 (GA) — Scoring — MUST** produce an **explainable weighted score**
  across five dimensions — **red execution 25%, detection 25%, investigation
  20%, response 20%, collaboration 10%** — returning every dimension's raw score,
  weight, and contribution, each penalty, and **every instructor override
  audited** with a named approver and written justification. A **derived score
  MUST exist from observed activity before any human judgement** is applied.
  *Evidence:* full score breakdown + an override audit entry.
- **Req 3.4.5 (GA) — Purple — MUST** report purple exercises as a
  **baseline-to-replay coverage delta per technique and in aggregate**, never as
  win/lose. *Evidence:* a purple comparison report.
- **Req 3.4.6 (GA) — Reporting — MUST** export after-action reports (technique
  coverage, detection gaps, evidence inventory, recommendations) in **JSON, CSV,
  HTML, and DOCX**, and class gradebooks in CSV. *Evidence:* the four report
  exports.

### 3.5 Integrations

- **Req 3.5.1 (GA) — MUST** ship optional **real SIEM** integration (bundled
  Wazuh: manager, indexer, dashboard) that ingests normalized event JSON, raises
  genuine alerts from the platform's detection rules, and posts those alerts back
  onto the exercise timeline as `basis=siem` detections, simultaneously visible
  in the SIEM dashboard. The telemetry contract MUST be **normalized** so
  substituting **Elastic, Microsoft Sentinel, or Splunk** is a configuration/
  adapter exercise, not a redesign. *(Wazuh: GA; additional SIEM adapters: P1.)*
  *Evidence:* a SIEM alert appearing as a timeline detection.
- **Req 3.5.2 (GA) — MUST** expose a complete **REST/JSON API** (bearer-token
  auth) for every dashboard action, with structured status codes
  (400/401/403/404/409/500) and filterable catalog queries, so the platform
  integrates with existing LMS, ticketing, and analytics pipelines rather than
  requiring operators to live in its UI. *Evidence:* API reference + a scripted
  exercise run.
- **Req 3.5.3 — MUST** provide **host- and network-sensor telemetry** (kernel
  runtime sensing via Falco; network IDS via Suricata/Zeek) feeding the same
  normalized detection contract, for higher-fidelity blue-team hunting. *(P1 —
  the telemetry contract is GA; the additional sensors are accepted at go-live.)*

### 3.6 Framework crosswalks

- **Req 3.6.1 (GA) — MUST** crosswalk techniques to **NIST CSF 2.0**, the **NICE
  Workforce Framework (SP 800-181r1)**, **CIS Controls v8**, and **NSA/DHS
  CAE-CD Knowledge Units**, served through the API for curriculum mapping and
  accreditation evidence, and presented as a curated curriculum alignment (not an
  official MITRE dataset). *Evidence:* `/api/frameworks`.

---

## 4. Security and administration

### 4.1 Access controls (RBAC)

- **Req 4.1.1 (GA) — MUST** enforce a role→permission mapping **server-side on
  every API call**, with distinct least-privilege roles (admin, instructor, red,
  blue, purple, solo, read-only security leader). Red MUST NOT execute S2; blue
  MUST NOT execute attacker modules; only admin MUST be able to provision users
  or release a quarantined range. *Acceptance:* each role is blocked from
  out-of-scope actions. *Evidence:* the live permission matrix (`/api/roles`) +
  denied-action logs.

### 4.2 Authentication

- **Req 4.2.1 (GA) — MUST** store passwords as **PBKDF2-HMAC-SHA256 with a
  per-user random salt** (never plaintext), issue **opaque random session tokens
  with a bounded TTL (≤ 12 h)**, return **non-enumerating** login errors
  (identical response for unknown user / wrong password / disabled account), and
  **immediately revoke all live sessions** when a user is disabled. *Evidence:*
  auth configuration + a disable-then-denied test.
- **Req 4.2.2 — MUST** support enterprise **SSO/OIDC** (SAML/OIDC IdP) with the
  RBAC layer unchanged — an identity integration, not a permissions redesign.
  *(P1 — the identity layer is isolated from RBAC in the GA build, so SSO is an
  adapter at the edge; accepted at go-live against a live IdP login.)*

### 4.3 Tenant isolation

- **Req 4.3.1 (GA) — MUST** isolate ranges on per-range **no-egress** networks,
  label every artifact by range ID, run all execution **non-privileged and
  resource-capped**, and keep the control plane unreachable from tenant
  workloads. *Acceptance:* a cross-range reachability test fails. *Evidence:*
  network policy + test log.
- **Req 4.3.2 — MUST** provide **logical multi-tenant separation** (org/tenant
  scoping of users, classes, ranges, evidence, and reports) on the managed tier,
  so one tenant cannot read another's data. *(P1 — accepted at go-live via a
  two-tenant isolation test; on-prem single-tenant isolation is GA.)*

### 4.4 Encryption

- **Req 4.4.1 (GA) — MUST** serve all remote access over **TLS** (managed on the
  hosted tier; Purchaser-terminated on-prem) and MUST support **encryption at
  rest** for the datastore (PostgreSQL TDE or encrypted volume; SQLite on an
  encrypted volume). *Evidence:* TLS configuration + at-rest encryption
  attestation.

### 4.5 Audit logs & data residency

- **Req 4.5.1 (GA) — MUST** write every state change to an **append-only audit
  ledger** readable by admins, covering lifecycle transitions, module execution,
  score overrides, quarantine actions, and user management, each entry carrying
  actor, action, target, and UTC timestamp. *Evidence:* `/api/audit` output.
- **Req 4.5.2 — MUST** keep all data within Purchaser-controlled infrastructure
  on-prem *(GA)*, and MUST allow **region/jurisdiction selection with no
  out-of-region data movement** on the managed tier *(P1)*. *Evidence:* residency
  attestation.

### 4.6 Monitoring & administrative controls

- **Req 4.6.1 (GA) — MUST** expose a **health endpoint** reporting execution mode
  and component status, and MUST provide admin controls for user provisioning,
  image management, **emergency pause/kill**, quarantine release, and audited
  score override. *Evidence:* `/api/health` + an admin-panel walkthrough.
- **Req 4.6.2 — MUST** emit platform operational metrics/logs in a form a
  Purchaser SOC can ingest (structured logs; metrics endpoint). *(P1 — structured
  audit/event logs are GA; a dedicated metrics endpoint is accepted at go-live.)*

---

## 5. Acceptance criteria, demonstration & proof-of-concept

Every **GA** benchmark MUST be demonstrated **live at POC** on
Purchaser-witnessed infrastructure, with the named evidence artifact produced on
the spot. Every **P1** benchmark MUST be accepted against the **identical test**
at the contract go-live milestone. Both are contractual.

### 5.1 Measurable performance benchmarks

| # | Benchmark | Pass criterion | Evidence | Delivery |
|---|---|---|---|---|
| B1 | Install footprint | Full control plane on 2-core/4 GB/2 GB-disk | `/api/health` + completed exercise | GA |
| B2 | Air-gapped install | Install + full exercise with host egress blocked | Firewall log + report | GA |
| B3 | Deploy time | Running dashboard + API from a clean host in **≤ 30 min** | Timed transcript | GA |
| B4 | Real execution fidelity | Genuine stdout/stderr/exit/timing captured in a network-isolated, capped, non-privileged, no-mount, auto-removed container | Timeline `real:true` + run spec | GA |
| B5 | Graceful degradation | With the execution host disabled, exercise still runs, scores, reports, labels events `sim` | Mixed-mode timeline | GA |
| B6 | Fog-of-war redaction | Defender view carries zero attacker attribution/command lines | Operator vs. defender query diff | GA |
| B7 | Auto-detection + MTTD | Rule fires automatically on real output; MTTD recorded | Detection record | GA |
| B8 | Explainable scoring | Score returns per-dimension raw/weight/contribution + audited overrides | Score breakdown | GA |
| B9 | Concurrency | Sustain quoted concurrent ranges/users; **median API latency < 500 ms, p95 < 1500 ms** | Load-test transcript | GA |
| B10 | Backup/restore | Restore to a clean host; evidence hashes verify; resume ops (**RPO ≤ 24 h, RTO ≤ 4 h**; ≤ 15 min RPO with PITR) | Restore transcript | GA (PITR: P1) |
| B11 | Safety enforcement | Unsigned/prohibited/over-privileged action refused **in the execution path** | Refusal + audit entry | GA |
| B12 | Reporting formats | After-action report exports JSON, CSV, HTML, DOCX | Four files | GA |
| B13 | Customer authoring | Evaluator authors, signs, and runs a new scenario without vendor code | Authored config + run | GA |
| B14 | Portability | Switch SQLite→Postgres and built-in detection→real SIEM by configuration only | Both backends + SIEM alert | GA |
| B15 | Horizontal scale | Two stateless control-plane replicas on one Postgres stay consistent | Dual-replica transcript | GA |
| B16 | Windows/AD fidelity | Live AD enumeration + attack path against a real domain controller | AD exercise timeline | P1 |
| B17 | SSO/OIDC | Login via the Purchaser's IdP; RBAC unchanged | Live IdP login | P1 |
| B18 | Multi-tenant isolation | Two tenants; neither can read the other's data | Two-tenant isolation test | P1 |
| B19 | HA failover | Control-plane node loss with no exercise data loss | Failover transcript | P1 |

### 5.2 Demonstration requirements

- **Req 5.2.1 (GA) — MUST** run a **live red→blue exercise** end to end: red
  executes a real technique; blue hunts it in the redacted SOC search with no
  foreknowledge; detection fires and records MTTD; a five-dimension score and an
  after-action report are produced.
- **Req 5.2.2 (GA) — MUST** demonstrate the **governance path**: unsigned-module
  refusal, S2 gating, auto-quarantine with admin-only release, and the
  append-only audit ledger.
- **Req 5.2.3 (P1) — MUST** demonstrate, at go-live, the **AD attack-path
  exercise** against a real domain controller and **SSO login** via the
  Purchaser's IdP.

### 5.3 Supporting evidence (with the bid)

- **Req 5.3.1 (GA) — MUST** supply an automated **test suite that runs on the
  standard library with no external services** (tests requiring Docker/Postgres
  skip cleanly) and report pass counts. The suite covers the API surface,
  lifecycle state machine, detection engine, execution adapters, scoring,
  log-search redaction, persistence (incl. the Postgres path), learning
  platform, SIEM integration, and user management. *Evidence:* test run output.
- **Req 5.3.2 (GA) — MUST** supply the **live capability counts via the catalog
  API** (scenarios, behavior modules, real-execution modules, ATT&CK techniques,
  detection rules, topology templates) so every claimed number is
  **independently verifiable at POC**, not asserted in prose.
- **Req 5.3.3 (P1) — MUST** supply, at go-live, acceptance evidence for each P1
  benchmark (B16–B19, PITR) against the identical tests above.

### 5.4 Proposed POC and staged-acceptance plan

**POC (2–3 days, witnessed, GA scope):**

1. **Day 1 — Deploy & isolate:** B1, B2, B3; walk the lifecycle state machine;
   verify B13 customer authoring.
2. **Day 2 — Fidelity & defence:** B4–B8 via a live red→blue exercise; B11
   governance path; B15 horizontal scale.
3. **Day 3 — Operate & verify:** B9 concurrency, B10 backup/restore, B12
   reporting, B14 portability; verify all capability counts against the catalog
   API (B/Req 5.3.2).

**Go-live staged acceptance (P1 scope):** B16 Windows/AD fidelity, B17 SSO/OIDC,
B18 multi-tenant isolation, B19 HA failover, and PITR backup — each witnessed
against the identical acceptance test defined above.

**Scoring:** each MUST is pass/fail; each SHOULD is weighted. A bidder claiming
compliance on any requirement MUST evidence it — live at POC for GA scope, or at
go-live for committed scope — against these exact tests. Votal AI holds itself to
the same standard: GA is demonstrated at POC; committed capability is accepted at
go-live, and both are contractual.

---

*This specification was prepared from Votal AI's CyberRange build. GA capability
counts reflect the current catalog and are verifiable through the platform's own
API at POC; committed (P1) capabilities are accepted at go-live against the
identical acceptance tests stated here.*
